//! The "auto-explain" report and the file map.
//!
//! [`map_file`] cuts a whole file into regions: a byte-statistics pass labels
//! every block (text, padding, code, high entropy, …), then confident
//! findings from the plugin registry (parsed images, archives, verified
//! compressed streams, executables) override the guesses for their extents.
//! [`explain`] turns those regions into a short plain-English report whose
//! sentences point at the bytes they describe.
//!
//! Both are pure functions meant to run on a background thread.

use eframe::egui::Color32;

use crate::analysis::shannon_entropy;
use crate::compress::human_bytes;
use crate::plugin::{Category, Finding, Registry, ScanContext};

/// What a region of the file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegionKind {
    Header,
    Code,
    Text,
    Data,
    Compressed,
    Encrypted,
    Padding,
    Image,
    Audio,
    Video,
    Archive,
    Filesystem,
    Executable,
    Unknown,
}

impl RegionKind {
    pub const ALL: [RegionKind; 14] = [
        RegionKind::Header,
        RegionKind::Code,
        RegionKind::Text,
        RegionKind::Data,
        RegionKind::Compressed,
        RegionKind::Encrypted,
        RegionKind::Padding,
        RegionKind::Image,
        RegionKind::Audio,
        RegionKind::Video,
        RegionKind::Archive,
        RegionKind::Filesystem,
        RegionKind::Executable,
        RegionKind::Unknown,
    ];

    /// The kind whose label is `label`; anything else is unknown.
    pub fn from_label(label: &str) -> RegionKind {
        RegionKind::ALL.into_iter().find(|kind| kind.label() == label).unwrap_or(RegionKind::Unknown)
    }

    pub fn label(self) -> &'static str {
        match self {
            RegionKind::Header => "header",
            RegionKind::Code => "machine code",
            RegionKind::Text => "text",
            RegionKind::Data => "binary data",
            RegionKind::Compressed => "compressed stream",
            RegionKind::Encrypted => "compressed or encrypted data",
            RegionKind::Padding => "padding",
            RegionKind::Image => "image",
            RegionKind::Audio => "audio",
            RegionKind::Video => "video",
            RegionKind::Archive => "archive",
            RegionKind::Filesystem => "filesystem",
            RegionKind::Executable => "executable",
            RegionKind::Unknown => "unknown",
        }
    }

    /// A distinct, readable colour for the file map.
    pub fn colour(self) -> Color32 {
        match self {
            RegionKind::Header => Color32::from_rgb(240, 200, 90),
            RegionKind::Code => Color32::from_rgb(235, 110, 110),
            RegionKind::Text => Color32::from_rgb(110, 170, 255),
            RegionKind::Data => Color32::from_rgb(120, 130, 150),
            RegionKind::Compressed => Color32::from_rgb(250, 236, 110),
            RegionKind::Encrypted => Color32::from_rgb(205, 145, 70),
            RegionKind::Padding => Color32::from_rgb(55, 60, 72),
            RegionKind::Image => Color32::from_rgb(255, 150, 200),
            RegionKind::Audio => Color32::from_rgb(120, 220, 170),
            RegionKind::Video => Color32::from_rgb(170, 130, 255),
            RegionKind::Archive => Color32::from_rgb(230, 140, 220),
            RegionKind::Filesystem => Color32::from_rgb(170, 200, 120),
            RegionKind::Executable => Color32::from_rgb(255, 110, 70),
            RegionKind::Unknown => Color32::from_rgb(90, 95, 105),
        }
    }
}

/// A run of bytes with one interpretation.
#[derive(Clone, Debug, PartialEq)]
pub struct Region {
    pub start: usize,
    pub len: usize,
    pub kind: RegionKind,
    pub label: String,
    pub detail: String,
    /// True when a parser or verified decoder identified the region; false
    /// when it is a statistical guess.
    pub confident: bool,
}

impl Region {
    pub fn end(&self) -> usize {
        self.start + self.len
    }
}

/// One sentence of the report, pointing at the bytes it describes.
#[derive(Clone, Debug, PartialEq)]
pub struct Sentence {
    pub text: String,
    pub start: usize,
    pub len: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    pub headline: String,
    pub sentences: Vec<Sentence>,
}

/// Files larger than this are scanned in sampled windows.
pub const SAMPLING_THRESHOLD: usize = 64 * 1024 * 1024;
const SCAN_WINDOW: usize = 1024 * 1024;
/// Overlap between scan windows, so findings straddling a boundary are seen.
const SCAN_OVERLAP: usize = 64 * 1024;
const MIN_BLOCK: usize = 1024;
const MAX_BLOCKS: usize = 4096;
const MIN_FINDING_CONFIDENCE: f32 = 0.7;

// ---------------------------------------------------------------------------
// Block classification
// ---------------------------------------------------------------------------

/// Classify one block from its byte statistics.
///
/// * padding: one byte value makes up at least 95% of the block;
/// * text: at least 90% printable ASCII;
/// * high entropy: at least 7.5 bits per byte, which compressed and encrypted
///   data reach and almost nothing else does;
/// * code: entropy between 5.0 and 6.6 with little text and few zeros, the
///   band where machine code typically sits;
/// * the first block of the file, if none of the above, is a header;
/// * anything else is binary data.
fn classify_block(block: &[u8], is_first: bool) -> RegionKind {
    if block.is_empty() {
        return RegionKind::Unknown;
    }
    let mut counts = [0usize; 256];
    for &byte in block {
        counts[byte as usize] += 1;
    }
    let len = block.len() as f32;
    let most_common = *counts.iter().max().unwrap_or(&0) as f32 / len;
    let printable = block.iter().filter(|&&b| (0x20..0x7F).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r')).count() as f32 / len;
    let zeros = counts[0] as f32 / len;
    let entropy = shannon_entropy(block);
    if most_common >= 0.95 {
        RegionKind::Padding
    } else if printable >= 0.9 {
        RegionKind::Text
    } else if entropy >= 7.5 {
        RegionKind::Encrypted
    } else if (5.0..=6.6).contains(&entropy) && printable < 0.6 && zeros < 0.3 {
        RegionKind::Code
    } else if is_first {
        RegionKind::Header
    } else {
        RegionKind::Data
    }
}

fn heuristic_region(start: usize, len: usize, kind: RegionKind, bytes: &[u8]) -> Region {
    let detail = match kind {
        RegionKind::Padding => {
            let block = &bytes[start..start + len.min(bytes.len() - start)];
            let value = block.first().copied().unwrap_or(0);
            format!("0x{value:02X} repeated")
        }
        RegionKind::Encrypted => format!("entropy {:.2} bits per byte", shannon_entropy(&bytes[start..start + len])),
        _ => String::new(),
    };
    Region { start, len, kind, label: kind.label().to_string(), detail, confident: false }
}

fn block_regions(bytes: &[u8]) -> Vec<Region> {
    let block = MIN_BLOCK.max(bytes.len().div_ceil(MAX_BLOCKS));
    let kinds: Vec<RegionKind> = bytes.chunks(block).enumerate().map(|(i, chunk)| classify_block(chunk, i == 0)).collect();
    let mut regions: Vec<Region> = Vec::new();
    let mut start = 0;
    for (index, &kind) in kinds.iter().enumerate() {
        let next_differs = kinds.get(index + 1) != Some(&kind);
        if next_differs {
            let end = ((index + 1) * block).min(bytes.len());
            regions.push(heuristic_region(start, end - start, kind, bytes));
            start = end;
        }
    }
    regions
}

// ---------------------------------------------------------------------------
// Findings overlay
// ---------------------------------------------------------------------------

/// The region kind a confident finding stands for, if it is one worth mapping.
/// Whether a catalogue finding measured how long its object is, rather than
/// covering only the magic bytes it matched (see `catalog::Catalog`).
fn catalogue_extent_known(finding: &Finding) -> bool {
    finding.detail.contains(" bytes")
}

fn finding_kind(finding: &Finding) -> Option<RegionKind> {
    if finding.confidence < MIN_FINDING_CONFIDENCE {
        return None;
    }
    // A bare magic-number match ("an ICO of 4 B") is too weak to describe a
    // region, whatever category the catalogue files it under.
    if finding.id.starts_with("signature:") && !catalogue_extent_known(finding) {
        return None;
    }
    let mime = finding.detail.to_ascii_lowercase();
    let by_mime = || {
        if mime.starts_with("image/") {
            Some(RegionKind::Image)
        } else if mime.starts_with("audio/") {
            Some(RegionKind::Audio)
        } else if mime.starts_with("video/") {
            Some(RegionKind::Video)
        } else {
            None
        }
    };
    match finding.category {
        Category::Executable => Some(RegionKind::Executable),
        Category::Image => Some(RegionKind::Image),
        Category::Archive => Some(RegionKind::Archive),
        Category::Filesystem => Some(RegionKind::Filesystem),
        Category::Compressed => Some(RegionKind::Compressed),
        Category::Document => Some(by_mime().unwrap_or(RegionKind::Data)),
        Category::Signature if finding.id.starts_with("signature:") => Some(by_mime().unwrap_or(RegionKind::Data)),
        _ => None,
    }
}

/// Start offsets of the windows the registry scans.
fn scan_offsets(len: usize) -> Vec<usize> {
    if len <= SAMPLING_THRESHOLD {
        (0..len.max(1)).step_by(SCAN_WINDOW - SCAN_OVERLAP).collect()
    } else {
        // Sample 64 evenly spaced windows.
        let windows = SAMPLING_THRESHOLD / SCAN_WINDOW;
        (0..windows).map(|i| i * (len - SCAN_WINDOW) / (windows - 1)).collect()
    }
}

/// The `[start, end)` windows a whole-file scan covers: all of a small file,
/// with overlaps so nothing straddling a boundary is missed, or an even
/// sample of a large one.
pub(crate) fn scan_windows(len: usize) -> Vec<(usize, usize)> {
    scan_offsets(len).into_iter().map(|start| (start, (start + SCAN_WINDOW).min(len))).collect()
}

fn confident_regions(bytes: &[u8], registry: &Registry) -> Vec<Region> {
    let mut found: Vec<(Region, f32)> = Vec::new();
    for (start, end) in scan_windows(bytes.len()) {
        let context = ScanContext { base: start, document_len: bytes.len(), strides: Vec::new() };
        for finding in registry.scan(&bytes[start..end], &context) {
            let Some(kind) = finding_kind(&finding) else { continue };
            let len = finding.len.min(bytes.len().saturating_sub(finding.start));
            if len == 0 {
                continue;
            }
            let region = Region {
                start: finding.start,
                len,
                kind,
                label: if finding.title.is_empty() { kind.label().to_string() } else { finding.title.clone() },
                detail: finding.detail.clone(),
                confident: true,
            };
            found.push((region, finding.confidence));
        }
    }
    // Keep the most confident, then largest, of overlapping findings.
    found.sort_by(|(a, ca), (b, cb)| cb.total_cmp(ca).then(b.len.cmp(&a.len)).then(a.start.cmp(&b.start)));
    let mut kept: Vec<Region> = Vec::new();
    for (region, _) in found {
        if kept.iter().all(|k| region.end() <= k.start || region.start >= k.end()) {
            kept.push(region);
        }
    }
    kept.sort_by_key(|r| r.start);
    kept
}

/// Cut `regions` so nothing overlaps `[start, end)`.
fn carve(regions: Vec<Region>, start: usize, end: usize, bytes: &[u8]) -> Vec<Region> {
    let mut out = Vec::with_capacity(regions.len() + 1);
    for region in regions {
        if region.end() <= start || region.start >= end {
            out.push(region);
            continue;
        }
        if region.start < start {
            out.push(heuristic_region(region.start, start - region.start, region.kind, bytes));
        }
        if region.end() > end {
            out.push(heuristic_region(end, region.end() - end, region.kind, bytes));
        }
    }
    out
}

/// Merge neighbouring guesses of the same kind, and fold guesses smaller than
/// 1% of the file into a neighbouring guess. Confident regions are never
/// absorbed.
fn tidy(mut regions: Vec<Region>, total: usize, bytes: &[u8]) -> Vec<Region> {
    regions.sort_by_key(|r| r.start);
    let sliver = total / 100;
    let mut changed = true;
    while changed {
        changed = false;
        let mut out: Vec<Region> = Vec::with_capacity(regions.len());
        let mut index = 0;
        while index < regions.len() {
            let region = regions[index].clone();
            let mergeable_with_previous = out.last().is_some_and(|prev: &Region| !prev.confident && !region.confident);
            let same_kind = out.last().is_some_and(|prev| prev.kind == region.kind);
            if mergeable_with_previous && (same_kind || region.len < sliver) {
                let prev = out.pop().expect("checked above");
                out.push(heuristic_region(prev.start, region.end() - prev.start, prev.kind, bytes));
                changed = true;
            } else if !region.confident
                && region.len < sliver
                && out.last().is_none_or(|prev| prev.confident)
                && regions.get(index + 1).is_some_and(|next| !next.confident)
            {
                // A leading sliver joins the guess after it.
                let next = regions[index + 1].clone();
                out.push(heuristic_region(region.start, next.end() - region.start, next.kind, bytes));
                index += 1;
                changed = true;
            } else {
                out.push(region);
            }
            index += 1;
        }
        regions = out;
    }
    regions
}

/// Segment the whole file into regions covering it in order without gaps.
pub fn map_file(bytes: &[u8], registry: &Registry) -> Vec<Region> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut regions = block_regions(bytes);
    for finding in confident_regions(bytes, registry) {
        regions = carve(regions, finding.start, finding.end(), bytes);
        regions.push(finding);
    }
    tidy(regions, bytes.len(), bytes)
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

fn article(word: &str) -> &'static str {
    match word.chars().next().map(|c| c.to_ascii_lowercase()) {
        Some('a' | 'e' | 'i' | 'o' | 'u') => "an",
        _ => "a",
    }
}

/// Fraction of the file covered by guesses of `kind`.
fn coverage(regions: &[Region], kind: RegionKind, total: usize) -> f32 {
    regions.iter().filter(|r| r.kind == kind).map(|r| r.len).sum::<usize>() as f32 / total.max(1) as f32
}

fn sampled_entropy(bytes: &[u8]) -> f32 {
    if bytes.len() <= SAMPLING_THRESHOLD {
        return shannon_entropy(bytes);
    }
    let step = bytes.len() / 64;
    let sample: Vec<u8> = (0..64).flat_map(|i| bytes[i * step..(i * step + 65536).min(bytes.len())].iter().copied()).collect();
    shannon_entropy(&sample)
}

/// Labels shown in a headline listing several things, then "and N more".
const HEADLINE_LABELS: usize = 4;
/// Share of a file framed messages must cover to name it a capture of them.
const FRAMED_COVERAGE: f64 = 0.9;
/// Messages a framing must find before a file is named a capture of them.
const FRAMED_MESSAGES: usize = 20;
/// Bytes from the start a framing is looked for in.
const FRAMING_SAMPLE: usize = 1024 * 1024;

/// `labels` as a list of at most `shown`, then "and N more".
fn listed(labels: &[String], shown: usize) -> String {
    let more = if labels.len() > shown { format!(" and {} more", labels.len() - shown) } else { String::new() };
    format!("{}{more}", labels.iter().take(shown).cloned().collect::<Vec<_>>().join(", "))
}

/// Each distinct label of `regions`, in order.
fn distinct_labels<'a>(regions: impl Iterator<Item = &'a Region>) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    for region in regions {
        if !labels.contains(&region.label) {
            labels.push(region.label.clone());
        }
    }
    labels
}

/// A disk image's headline, when the file starts with a partition table:
/// the table and the filesystems, then what they hold.
fn disk_headline(confident: &[&Region]) -> Option<String> {
    let table = confident.first().filter(|first| first.start == 0 && first.label.contains("partition table"))?;
    let (volumes, contents): (Vec<&Region>, Vec<&Region>) = confident.iter().skip(1).partition(|region| region.kind == RegionKind::Filesystem);
    let mut structure = vec![table.label.clone()];
    structure.extend(distinct_labels(volumes.into_iter()));
    let contents = distinct_labels(contents.into_iter());
    let holding = if contents.is_empty() { String::new() } else { format!(", holding {}", listed(&contents, HEADLINE_LABELS - 1)) };
    Some(format!("Disk image: {}{holding}", listed(&structure, HEADLINE_LABELS)))
}

/// A capture of framed messages' headline, when a sync word or length
/// field frames nearly all of the file's start: a raw bus or serial dump,
/// whose bytes look like code or data to the statistics.
fn framed_headline(bytes: &[u8]) -> Option<String> {
    use crate::protocol::Framing;
    let sample = &bytes[..bytes.len().min(FRAMING_SAMPLE)];
    let best = crate::protocol::detect_framing(sample, 1).into_iter().next()?;
    let framed = matches!(best.framing, Framing::SyncWord { .. } | Framing::SyncLength { .. } | Framing::LengthPrefixed { .. });
    (framed && best.coverage >= FRAMED_COVERAGE && best.messages >= FRAMED_MESSAGES)
        .then(|| format!("Framed messages: {}", best.framing.describe()))
}

fn headline(regions: &[Region], bytes: &[u8]) -> String {
    let total = bytes.len();
    let confident: Vec<&Region> = regions.iter().filter(|r| r.confident).collect();
    if let Some(first) = confident.first()
        && first.start == 0
        && first.len * 10 >= total * 9
    {
        return capitalise(&first.label);
    }
    if let Some(disk) = disk_headline(&confident) {
        return disk;
    }
    let labels = distinct_labels(confident.iter().copied());
    if labels.len() >= 2 {
        return format!("Composite, firmware-like image: {}", listed(&labels, HEADLINE_LABELS));
    }
    if let Some(only) = confident.first() {
        return if only.len * 2 >= total { capitalise(&only.label) } else { format!("File containing {} {}", article(&only.label), only.label) };
    }
    let mostly_text = coverage(regions, RegionKind::Text, total) >= 0.7;
    if !mostly_text && let Some(framed) = framed_headline(bytes) {
        return framed;
    }
    if mostly_text {
        "Text".to_string()
    } else if coverage(regions, RegionKind::Encrypted, total) >= 0.7 {
        "Compressed or encrypted data".to_string()
    } else if coverage(regions, RegionKind::Padding, total) >= 0.7 {
        "Mostly empty: padding".to_string()
    } else if coverage(regions, RegionKind::Code, total) >= 0.5 {
        "Looks like machine code".to_string()
    } else {
        "Binary data".to_string()
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// What the whole file most likely is, in a few words for the opening sentence.
fn likely_nature(headline: &str) -> String {
    let lower = headline.to_lowercase();
    if lower.starts_with("composite") {
        "looks like a composite or firmware-like image".to_string()
    } else if lower.starts_with("disk image") || lower.starts_with("framed messages") {
        format!("looks like {}", lower.replacen("disk image", "a disk image", 1).replacen("framed messages", "a capture of framed messages", 1))
    } else if lower.starts_with("looks like") {
        lower
    } else {
        format!("looks like {}", lower)
    }
}

fn sentence_for(region: &Region) -> String {
    let size = human_bytes(region.len);
    if region.confident {
        let detail = if region.detail.is_empty() { String::new() } else { format!(" ({})", region.detail) };
        format!("At {:#x}, {} {} of {size}{detail}.", region.start, article(&region.label), region.label, size = size)
    } else {
        let detail = if region.detail.is_empty() { String::new() } else { format!(", {}", region.detail) };
        format!("At {:#x}, {size} that looks like {}{detail}.", region.start, region.label)
    }
}

/// Describe the file in plain English from its regions.
pub fn explain(bytes: &[u8], name: &str, regions: &[Region]) -> Report {
    let total = bytes.len();
    let headline = headline(regions, bytes);
    let entropy = sampled_entropy(bytes);
    let mut sentences = vec![Sentence {
        text: format!(
            "{name} is {} with an overall entropy of {entropy:.2} bits per byte; it {}.",
            human_bytes(total),
            likely_nature(&headline)
        ),
        start: 0,
        len: total,
    }];
    let notable = (total / 50).max(4096).min(total);
    for region in regions {
        if region.confident || region.len >= notable {
            sentences.push(Sentence { text: sentence_for(region), start: region.start, len: region.len });
        }
    }
    if total > SAMPLING_THRESHOLD {
        sentences.push(Sentence {
            text: format!(
                "The file is larger than {}, so findings come from 64 sampled windows of 1 MiB and parts may be missed.",
                human_bytes(SAMPLING_THRESHOLD)
            ),
            start: 0,
            len: 0,
        });
    }
    Report { headline, sentences }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    fn png() -> Vec<u8> {
        let image = image::RgbaImage::from_fn(48, 32, |x, y| image::Rgba([x as u8 * 5, y as u8 * 7, 100, 255]));
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image).write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    fn assert_covers(regions: &[Region], total: usize) {
        assert_eq!(regions.first().map(|r| r.start), Some(0));
        for pair in regions.windows(2) {
            assert_eq!(pair[0].end(), pair[1].start, "gap or overlap: {pair:#?}");
        }
        assert_eq!(regions.last().map(|r| r.end()), Some(total));
    }

    #[test]
    fn a_firmware_like_file_is_mapped_and_explained() {
        let mut file = b"ACME FIRMWARE v2.1 build 2026-09-01 board rev C serial 00001234".to_vec();
        file.resize(64, b' ');
        file.extend_from_slice(&[0u8; 8192]);
        let gzip_at = file.len();
        let text: Vec<u8> = (0..400).flat_map(|i| format!("config line {i} value=on\n").into_bytes()).collect();
        let gzip = crate::compress::compress(crate::compress::Codec::Gzip, &text).unwrap();
        file.extend_from_slice(&gzip);
        let noise_at = file.len();
        file.extend_from_slice(&noise(16 * 1024));
        let png_at = file.len();
        let png = png();
        file.extend_from_slice(&png);

        let registry = crate::app::build_registry();
        let regions = map_file(&file, &registry);
        assert_covers(&regions, file.len());
        let kinds: Vec<RegionKind> = regions.iter().map(|r| r.kind).collect();
        let position = |kind: RegionKind| kinds.iter().position(|&k| k == kind).unwrap_or_else(|| panic!("{kind:?} in {regions:#?}"));
        assert!(position(RegionKind::Header) < position(RegionKind::Padding));
        assert!(position(RegionKind::Padding) < position(RegionKind::Compressed));
        assert!(position(RegionKind::Compressed) < position(RegionKind::Encrypted));
        assert!(position(RegionKind::Encrypted) < position(RegionKind::Image));
        let gzip_region = &regions[position(RegionKind::Compressed)];
        assert_eq!((gzip_region.start, gzip_region.len), (gzip_at, gzip.len()));
        let png_region = &regions[position(RegionKind::Image)];
        assert_eq!((png_region.start, png_region.len), (png_at, png.len()));
        assert!(regions[position(RegionKind::Encrypted)].start >= noise_at);

        let report = explain(&file, "firmware.bin", &regions);
        assert!(report.headline.starts_with("Composite"), "{}", report.headline);
        let mentions = |offset: usize, word: &str| {
            report.sentences.iter().any(|s| s.start == offset && s.text.to_lowercase().contains(word) && s.text.contains(&format!("{offset:#x}")))
        };
        assert!(mentions(gzip_at, "gzip"), "{report:#?}");
        assert!(mentions(png_at, "png"), "{report:#?}");
        assert!(report.sentences[0].text.starts_with("firmware.bin is"));
    }

    #[test]
    fn text_and_noise_are_described_honestly() {
        let registry = crate::app::build_registry();
        let text: Vec<u8> = (0..2000).flat_map(|i| format!("The quick brown fox {i} jumps over the lazy dog.\n").into_bytes()).collect();
        let regions = map_file(&text, &registry);
        assert_covers(&regions, text.len());
        assert_eq!(explain(&text, "notes.txt", &regions).headline, "Text");

        let random = noise(256 * 1024);
        let regions = map_file(&random, &registry);
        assert_covers(&regions, random.len());
        let report = explain(&random, "blob", &regions);
        assert_eq!(report.headline, "Compressed or encrypted data", "{regions:#?}");
        assert!(report.sentences[0].text.contains("looks like compressed or encrypted data"));
    }

    #[test]
    fn a_bare_magic_number_match_is_not_reported_as_an_object() {
        let magic_only = Finding::new("signature:image/vnd.microsoft.icon", "catalog", Category::Image, 0x9d, 4)
            .title("ICO")
            .detail("image/vnd.microsoft.icon · .ico")
            .confidence(0.9);
        assert_eq!(finding_kind(&magic_only), None);
        let measured = magic_only.clone().detail("image/vnd.microsoft.icon · .ico · 1406 bytes");
        assert_eq!(finding_kind(&measured), Some(RegionKind::Image));
    }

    #[test]
    fn empty_and_tiny_files_do_not_panic() {
        let registry = crate::app::build_registry();
        assert!(map_file(&[], &registry).is_empty());
        let tiny = b"hi".to_vec();
        let regions = map_file(&tiny, &registry);
        assert_covers(&regions, 2);
        let _ = explain(&tiny, "tiny", &regions);
        let _ = explain(&[], "empty", &[]);
    }

    fn confident(start: usize, len: usize, kind: RegionKind, label: &str) -> Region {
        Region { start, len, kind, label: label.to_string(), detail: String::new(), confident: true }
    }

    #[test]
    fn a_partitioned_disk_image_is_headlined_by_its_partition_table_and_filesystem() {
        let total = 9 * 1024 * 1024;
        let regions = vec![
            confident(0, 512, RegionKind::Filesystem, "MBR partition table"),
            heuristic_region(512, 1_048_064, RegionKind::Padding, &vec![0; total]),
            confident(1_048_576, 512, RegionKind::Filesystem, "FAT16 boot sector"),
            confident(1_102_848, 46_697, RegionKind::Image, "JPEG image"),
            confident(1_149_952, 6_019, RegionKind::Archive, "ZIP archive"),
        ];
        let report = explain(&vec![0; total], "usb_stick.dd", &regions);
        assert!(report.headline.starts_with("Disk image: MBR partition table, FAT16 boot sector"), "{}", report.headline);
        assert!(report.headline.contains("JPEG image"), "{}", report.headline);
        assert!(report.sentences[0].text.contains("looks like a disk image"), "{}", report.sentences[0].text);
    }

    /// A bus capture: frames of a sync word, a length, addresses, a
    /// sequence number, a type, a payload and a CRC, back to back.
    fn bus_capture() -> Vec<u8> {
        let mut bytes = noise(60_000);
        let mut stream = Vec::new();
        let mut taken = 0;
        for index in 0..2000usize {
            let payload_len = [0, 16, 4][index % 3];
            stream.extend([0xA5, 0x5A, (payload_len + 4) as u8, 0x01, 0x10 + (index % 3) as u8, index as u8, [0x01, 0x81, 0x10][index % 3]]);
            stream.extend(&bytes[taken..taken + payload_len + 2]);
            taken += payload_len + 2;
        }
        bytes.clear();
        stream
    }

    #[test]
    fn a_capture_of_framed_messages_is_not_called_machine_code() {
        let capture = bus_capture();
        let regions = vec![heuristic_region(0, capture.len(), RegionKind::Code, &capture)];
        let report = explain(&capture, "rs485_dump.bin", &regions);
        assert!(report.headline.starts_with("Framed messages"), "{}", report.headline);
        assert!(report.headline.contains("A5 5A"), "{}", report.headline);
    }
}
