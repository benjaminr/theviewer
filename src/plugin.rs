//! The plugin boundary: everything that recognises, parses, decodes or acts on
//! bytes implements one of the traits here and is registered in a
//! [`Registry`]. Built-in detectors are ordinary plugins, so third-party and
//! scripted ones get exactly the same treatment in the UI.
//!
//! * [`Detector`] scans a window of bytes and returns [`Finding`]s.
//! * [`Parser`] parses one structure at a given offset into a field tree.
//! * [`CodecPlugin`] decodes and encodes a block (compression or an encoding).
//!
//! A finding carries a broad [`Category`] for colour and filtering, a
//! confidence, and an optional field tree so the inspector can show structure.

use std::sync::Arc;

use eframe::egui::Color32;

/// Broad kinds of finding. Fixed so colours and filters are predictable;
/// plugins describe specifics in a finding's `id` and `title`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    Signature,
    Executable,
    Image,
    Archive,
    Document,
    Filesystem,
    Compressed,
    Encoding,
    Protocol,
    Structure,
    Timestamp,
    Counter,
    OffsetTable,
    FloatArray,
    Text,
    HighEntropy,
    Padding,
    Custom,
}

impl Category {
    pub const ALL: [Category; 18] = [
        Category::Signature,
        Category::Executable,
        Category::Image,
        Category::Archive,
        Category::Document,
        Category::Filesystem,
        Category::Compressed,
        Category::Encoding,
        Category::Protocol,
        Category::Structure,
        Category::Timestamp,
        Category::Counter,
        Category::OffsetTable,
        Category::FloatArray,
        Category::Text,
        Category::HighEntropy,
        Category::Padding,
        Category::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Signature => "File signatures",
            Category::Executable => "Executables",
            Category::Image => "Images",
            Category::Archive => "Archives",
            Category::Document => "Documents",
            Category::Filesystem => "Filesystems",
            Category::Compressed => "Compressed streams",
            Category::Encoding => "Encodings",
            Category::Protocol => "Protocols",
            Category::Structure => "Structures",
            Category::Timestamp => "Timestamps",
            Category::Counter => "Counters",
            Category::OffsetTable => "Offset tables",
            Category::FloatArray => "Float arrays",
            Category::Text => "Text",
            Category::HighEntropy => "High entropy",
            Category::Padding => "Padding",
            Category::Custom => "Plugin findings",
        }
    }

    pub fn index(self) -> usize {
        Category::ALL.iter().position(|&c| c == self).unwrap_or(0)
    }

    pub fn from_name(name: &str) -> Option<Category> {
        let name = name.to_ascii_lowercase();
        Category::ALL.into_iter().find(|c| {
            let label = c.label().to_ascii_lowercase();
            label == name || format!("{c:?}").to_ascii_lowercase() == name
        })
    }

    /// Highlight colour. Lives here rather than in the theme so plugins and
    /// the UI agree without a second table.
    pub fn colour(self) -> Color32 {
        match self {
            Category::Signature => Color32::from_rgb(235, 96, 88),
            Category::Executable => Color32::from_rgb(255, 120, 120),
            Category::Image => Color32::from_rgb(255, 170, 120),
            Category::Archive => Color32::from_rgb(230, 140, 200),
            Category::Document => Color32::from_rgb(200, 180, 255),
            Category::Filesystem => Color32::from_rgb(180, 200, 140),
            Category::Compressed => Color32::from_rgb(250, 236, 110),
            Category::Encoding => Color32::from_rgb(170, 230, 230),
            Category::Protocol => Color32::from_rgb(120, 200, 255),
            Category::Structure => Color32::from_rgb(190, 190, 255),
            Category::Timestamp => Color32::from_rgb(255, 150, 60),
            Category::Counter => Color32::from_rgb(235, 110, 205),
            Category::OffsetTable => Color32::from_rgb(165, 125, 255),
            Category::FloatArray => Color32::from_rgb(95, 210, 135),
            Category::Text => Color32::from_rgb(110, 170, 255),
            Category::HighEntropy => Color32::from_rgb(205, 175, 95),
            Category::Padding => Color32::from_rgb(115, 122, 135),
            Category::Custom => Color32::from_rgb(255, 255, 255),
        }
    }

    /// Cap on findings of this category per scan, so a text file does not
    /// produce ten thousand highlights.
    pub fn cap(self) -> usize {
        match self {
            Category::Text => 1500,
            Category::Padding => 1000,
            _ => 800,
        }
    }
}

/// One parsed field of a structure, with its byte extent so the UI can
/// highlight it. `children` nests sub-structures.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Field {
    pub name: String,
    pub offset: usize,
    pub len: usize,
    pub value: String,
    pub children: Vec<Field>,
}

impl Field {
    pub fn new(name: impl Into<String>, offset: usize, len: usize, value: impl Into<String>) -> Self {
        Field { name: name.into(), offset, len, value: value.into(), children: Vec::new() }
    }

    pub fn with_children(mut self, children: Vec<Field>) -> Self {
        self.children = children;
        self
    }

    pub fn end(&self) -> usize {
        self.offset + self.len
    }

    /// The innermost field containing `offset`, with the path of names to it.
    pub fn find_at(&self, offset: usize) -> Option<Vec<&Field>> {
        if offset < self.offset || offset >= self.end() {
            return None;
        }
        let mut path = vec![self];
        if let Some(mut inner) = self.children.iter().find_map(|child| child.find_at(offset)) {
            path.append(&mut inner);
        }
        Some(path)
    }
}

/// Extra facts about a strided sequence (counters, timestamps, arrays).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sequence {
    /// Bytes between elements.
    pub stride: usize,
    pub count: usize,
    /// Bytes per element.
    pub element: usize,
}

/// Something recognised in the bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    /// Stable identifier such as `signature:image/png` or `stream:zlib`.
    pub id: String,
    /// Which plugin produced it.
    pub source: String,
    pub category: Category,
    /// Document offset of the first byte.
    pub start: usize,
    /// Bytes spanned, including gaps between strided elements.
    pub len: usize,
    /// Short label, e.g. "PNG image".
    pub title: String,
    /// Longer description for tooltips and the findings panel.
    pub detail: String,
    /// 0 to 1. Below 0.5 the finding is drawn dimmed and loses overlap fights.
    pub confidence: f32,
    pub sequence: Option<Sequence>,
    /// Parsed structure, if the plugin understands the format.
    pub fields: Vec<Field>,
}

impl Finding {
    pub fn new(id: impl Into<String>, source: impl Into<String>, category: Category, start: usize, len: usize) -> Self {
        Finding {
            id: id.into(),
            source: source.into(),
            category,
            start,
            len,
            title: String::new(),
            detail: String::new(),
            confidence: 1.0,
            sequence: None,
            fields: Vec::new(),
        }
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn sequence(mut self, stride: usize, count: usize, element: usize) -> Self {
        self.sequence = Some(Sequence { stride, count, element });
        self
    }

    pub fn fields(mut self, fields: Vec<Field>) -> Self {
        self.fields = fields;
        self
    }

    pub fn end(&self) -> usize {
        self.start + self.len
    }

    pub fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end()
    }

    pub fn weak(&self) -> bool {
        self.confidence < 0.5
    }

    /// Title and detail joined, for places that show one line.
    pub fn description(&self) -> String {
        if self.detail.is_empty() {
            self.title.clone()
        } else if self.title.is_empty() {
            self.detail.clone()
        } else {
            format!("{}: {}", self.title, self.detail)
        }
    }

    /// Path of fields containing `offset`, outermost first.
    pub fn field_path(&self, offset: usize) -> Vec<&Field> {
        self.fields.iter().find_map(|field| field.find_at(offset)).unwrap_or_default()
    }
}

/// What a scan knows beyond the bytes themselves.
#[derive(Clone, Debug, Default)]
pub struct ScanContext {
    /// Document offset of `window[0]`.
    pub base: usize,
    /// Total document length.
    pub document_len: usize,
    /// Candidate record strides worth testing (row stride, detected periods).
    pub strides: Vec<usize>,
}

/// Scans a window of bytes for things it recognises.
pub trait Detector: Send + Sync {
    /// Stable identifier, e.g. `builtin.sequences` or `lua.my_dissector`.
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    /// Categories this detector can produce, for the filter UI.
    fn categories(&self) -> Vec<Category>;
    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding>;
}

/// Parses one structure starting at a given offset.
pub trait Parser: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    /// Cheap check on the first bytes; the registry only calls `parse` when
    /// this returns true, so scanning stays fast.
    fn looks_like(&self, bytes: &[u8]) -> bool;
    /// Parse the structure at `bytes[0]`, which sits at document offset
    /// `base`. Return `None` if the bytes do not parse.
    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding>;
}

/// Whether a codec is compression (sizes matter) or a representation change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecKind {
    Compression,
    Encoding,
}

/// Result of decoding a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub data: Vec<u8>,
    /// Input bytes used.
    pub consumed: usize,
    /// Whether `consumed` is exact rather than a buffered estimate.
    pub consumed_exact: bool,
    pub complete: bool,
    pub truncated: bool,
}

/// Decodes and optionally encodes a block of bytes.
pub trait CodecPlugin: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn kind(&self) -> CodecKind;
    /// Whether the start of `bytes` carries this codec's header. Headerless
    /// codecs return false and are only used by probing.
    fn detect(&self, bytes: &[u8]) -> bool;
    fn decode(&self, input: &[u8], max_out: usize) -> Result<Decoded, String>;
    /// `None` when the codec cannot encode.
    fn encode(&self, data: &[u8]) -> Option<Result<Vec<u8>, String>>;
}

/// Everything registered, in the order it was added.
#[derive(Default, Clone)]
pub struct Registry {
    detectors: Vec<Arc<dyn Detector>>,
    parsers: Vec<Arc<dyn Parser>>,
    codecs: Vec<Arc<dyn CodecPlugin>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_detector(&mut self, detector: impl Detector + 'static) -> &mut Self {
        self.detectors.push(Arc::new(detector));
        self
    }

    pub fn add_parser(&mut self, parser: impl Parser + 'static) -> &mut Self {
        self.parsers.push(Arc::new(parser));
        self
    }

    pub fn add_codec(&mut self, codec: impl CodecPlugin + 'static) -> &mut Self {
        self.codecs.push(Arc::new(codec));
        self
    }

    pub fn add_detector_arc(&mut self, detector: Arc<dyn Detector>) -> &mut Self {
        self.detectors.push(detector);
        self
    }

    pub fn add_parser_arc(&mut self, parser: Arc<dyn Parser>) -> &mut Self {
        self.parsers.push(parser);
        self
    }

    pub fn add_codec_arc(&mut self, codec: Arc<dyn CodecPlugin>) -> &mut Self {
        self.codecs.push(codec);
        self
    }

    pub fn detectors(&self) -> &[Arc<dyn Detector>] {
        &self.detectors
    }

    pub fn parsers(&self) -> &[Arc<dyn Parser>] {
        &self.parsers
    }

    pub fn codecs(&self) -> &[Arc<dyn CodecPlugin>] {
        &self.codecs
    }

    pub fn codec(&self, id: &str) -> Option<&Arc<dyn CodecPlugin>> {
        self.codecs.iter().find(|codec| codec.id() == id)
    }

    /// Run every detector over the window and gather their findings.
    pub fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        use rayon::prelude::*;
        let mut findings: Vec<Finding> = self
            .detectors
            .par_iter()
            .flat_map_iter(|detector| detector.scan(window, context))
            .collect();
        findings.sort_by(|a, b| a.start.cmp(&b.start).then(a.category.cmp(&b.category)));
        findings
    }

    /// Try every parser at `bytes[0]` (document offset `base`).
    pub fn parse_at(&self, bytes: &[u8], base: usize) -> Vec<Finding> {
        self.parsers
            .iter()
            .filter(|parser| parser.looks_like(bytes))
            .filter_map(|parser| parser.parse(bytes, base))
            .collect()
    }

    /// Codecs whose header matches the start of `bytes`.
    pub fn codecs_detecting(&self, bytes: &[u8]) -> Vec<&Arc<dyn CodecPlugin>> {
        self.codecs.iter().filter(|codec| codec.detect(bytes)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Marker;

    impl Detector for Marker {
        fn id(&self) -> &str {
            "test.marker"
        }
        fn name(&self) -> &str {
            "Marker"
        }
        fn categories(&self) -> Vec<Category> {
            vec![Category::Custom]
        }
        fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
            window
                .iter()
                .enumerate()
                .filter(|(_, b)| **b == 0xAB)
                .map(|(i, _)| Finding::new("marker", self.id(), Category::Custom, context.base + i, 1).title("AB"))
                .collect()
        }
    }

    #[test]
    fn registry_runs_detectors_and_orders_findings() {
        let mut registry = Registry::new();
        registry.add_detector(Marker);
        let findings = registry.scan(&[0, 0xAB, 0, 0xAB], &ScanContext { base: 100, document_len: 4, strides: vec![] });
        assert_eq!(findings.iter().map(|f| f.start).collect::<Vec<_>>(), vec![101, 103]);
        assert_eq!(findings[0].source, "test.marker");
    }

    #[test]
    fn field_lookup_returns_the_path_to_the_innermost_field() {
        let header = Field::new("header", 0, 8, "").with_children(vec![
            Field::new("magic", 0, 4, "PNG"),
            Field::new("length", 4, 4, "13"),
        ]);
        let finding = Finding::new("x", "t", Category::Image, 0, 8).fields(vec![header]);
        let path: Vec<&str> = finding.field_path(5).iter().map(|f| f.name.as_str()).collect();
        assert_eq!(path, vec!["header", "length"]);
        assert!(finding.field_path(9).is_empty());
    }

    #[test]
    fn descriptions_combine_title_and_detail() {
        let finding = Finding::new("x", "t", Category::Text, 0, 1).title("ASCII text").detail("12 chars");
        assert_eq!(finding.description(), "ASCII text: 12 chars");
        assert!(!finding.weak());
        assert!(Finding::new("x", "t", Category::Text, 0, 1).confidence(0.2).weak());
    }
}
