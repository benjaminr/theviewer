//! Image containers: PNG, JPEG, GIF and BMP, parsed by hand for exact field
//! offsets, plus a bounded thumbnail decoder built on the `image` crate.

use std::io::Cursor;

use image::{ImageReader, Limits};

use super::{MAX_CHILDREN, MAX_EXTENT, guarded, u16be, u16le, u32be, u32le};
use crate::plugin::{Category, Field, Finding, Parser};

const SOURCE: &str = "parsers.image";

/// A decoded, downscaled image for the UI to draw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub width: u32,
    pub height: u32,
    /// Row-major RGBA, 4 bytes per pixel.
    pub rgba: Vec<u8>,
}

/// Largest image dimension the preview decoder will accept.
const PREVIEW_MAX_SOURCE: u32 = 8192;
/// Memory the preview decoder may allocate.
const PREVIEW_MAX_ALLOC: u64 = 256 * 1024 * 1024;

/// Decode the image at the start of `bytes`, scaled to fit `max_dim`.
pub fn image_preview(bytes: &[u8], max_dim: u32) -> Option<Preview> {
    guarded(|| {
        let mut reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format().ok()?;
        let mut limits = Limits::default();
        limits.max_image_width = Some(PREVIEW_MAX_SOURCE);
        limits.max_image_height = Some(PREVIEW_MAX_SOURCE);
        limits.max_alloc = Some(PREVIEW_MAX_ALLOC);
        reader.limits(limits);
        let decoded = reader.decode().ok()?;
        let scaled = if decoded.width() > max_dim || decoded.height() > max_dim { decoded.thumbnail(max_dim, max_dim) } else { decoded };
        let rgba = scaled.to_rgba8();
        Some(Preview { width: rgba.width(), height: rgba.height(), rgba: rgba.into_raw() })
    })
}

// ---------------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------------

pub struct PngParser;

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

fn png_colour_type(value: u8) -> &'static str {
    match value {
        0 => "greyscale",
        2 => "RGB",
        3 => "palette",
        4 => "greyscale + alpha",
        6 => "RGBA",
        _ => "unknown",
    }
}

impl Parser for PngParser {
    fn id(&self) -> &str {
        "png"
    }

    fn name(&self) -> &str {
        "PNG image"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(PNG_SIGNATURE)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !bytes.starts_with(PNG_SIGNATURE) {
            return None;
        }
        let mut chunks = Vec::new();
        let mut at = 8;
        let mut dimensions = None;
        let mut complete = false;
        while at + 12 <= bytes.len() && chunks.len() < MAX_CHILDREN {
            let length = u32be(bytes, at)? as usize;
            let kind = &bytes[at + 4..at + 8];
            if !kind.iter().all(|b| b.is_ascii_alphabetic()) {
                break;
            }
            let kind_text = String::from_utf8_lossy(kind).to_string();
            let total = 12 + length;
            if at + total > bytes.len() || at + total > MAX_EXTENT {
                break;
            }
            let crc = u32be(bytes, at + 8 + length)?;
            let mut chunk = Field::new(kind_text.clone(), base + at, total, format!("{length} bytes, crc {crc:08x}"));
            if kind == b"IHDR" && length >= 13 {
                let data = at + 8;
                let width = u32be(bytes, data)?;
                let height = u32be(bytes, data + 4)?;
                let depth = bytes[data + 8];
                let colour = bytes[data + 9];
                dimensions = Some((width, height, depth, colour));
                chunk.children = vec![
                    Field::new("width", base + data, 4, width.to_string()),
                    Field::new("height", base + data + 4, 4, height.to_string()),
                    Field::new("bit depth", base + data + 8, 1, depth.to_string()),
                    Field::new("colour type", base + data + 9, 1, png_colour_type(colour)),
                    Field::new("interlace", base + data + 12, 1, bytes[data + 12].to_string()),
                ];
            }
            chunks.push(chunk);
            at += total;
            if kind == b"IEND" {
                complete = true;
                break;
            }
        }
        let (width, height, depth, colour) = dimensions?;
        let detail = format!(
            "PNG {width}×{height}, {depth}-bit {}, {} chunks{}",
            png_colour_type(colour),
            chunks.len(),
            if complete { "" } else { ", no IEND" }
        );
        let fields = vec![Field::new("signature", base, 8, "\\x89PNG\\r\\n\\x1a\\n"), Field::new("chunks", base + 8, at - 8, format!("{} chunks", chunks.len())).with_children(chunks)];
        Some(
            Finding::new("png", SOURCE, Category::Image, base, at)
                .title("PNG image")
                .detail(detail)
                .confidence(if complete { 1.0 } else { 0.7 })
                .fields(fields),
        )
    }
}

// ---------------------------------------------------------------------------
// JPEG
// ---------------------------------------------------------------------------

pub struct JpegParser;

fn jpeg_marker_name(marker: u8) -> String {
    match marker {
        0xD8 => "SOI".to_string(),
        0xD9 => "EOI".to_string(),
        0xDA => "SOS".to_string(),
        0xDB => "DQT".to_string(),
        0xC4 => "DHT".to_string(),
        0xDD => "DRI".to_string(),
        0xFE => "COM".to_string(),
        0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => format!("SOF{}", marker - 0xC0),
        0xE0..=0xEF => format!("APP{}", marker - 0xE0),
        _ => format!("marker {marker:#04x}"),
    }
}

impl Parser for JpegParser {
    fn id(&self) -> &str {
        "jpeg"
    }

    fn name(&self) -> &str {
        "JPEG image"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(&[0xFF, 0xD8, 0xFF])
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !bytes.starts_with(&[0xFF, 0xD8]) {
            return None;
        }
        let mut segments = vec![Field::new("SOI", base, 2, "start of image")];
        let mut at = 2;
        let mut dimensions = None;
        let mut complete = false;
        let mut exif_tags = 0;
        // Two bytes are enough to see a marker; the end-of-image marker has no length.
        while at + 2 <= bytes.len() && segments.len() < MAX_CHILDREN {
            if bytes[at] != 0xFF {
                break;
            }
            let marker = bytes[at + 1];
            if marker == 0xD9 {
                segments.push(Field::new("EOI", base + at, 2, "end of image"));
                at += 2;
                complete = true;
                break;
            }
            if marker == 0xFF || marker == 0x00 || (0xD0..=0xD7).contains(&marker) {
                at += if marker == 0xFF { 1 } else { 2 };
                continue;
            }
            let Some(length) = u16be(bytes, at + 2).map(usize::from) else { break };
            if length < 2 || at + 2 + length > bytes.len() {
                break;
            }
            let name = jpeg_marker_name(marker);
            let mut segment = Field::new(name.clone(), base + at, 2 + length, format!("{length} bytes"));
            if name.starts_with("SOF") && length >= 8 {
                let data = at + 4;
                let precision = bytes[data];
                let height = u16be(bytes, data + 1)?;
                let width = u16be(bytes, data + 3)?;
                let components = bytes[data + 5];
                dimensions = Some((width, height, precision, components));
                segment.children = vec![
                    Field::new("precision", base + data, 1, precision.to_string()),
                    Field::new("height", base + data + 1, 2, height.to_string()),
                    Field::new("width", base + data + 3, 2, width.to_string()),
                    Field::new("components", base + data + 5, 1, components.to_string()),
                ];
            }
            let segment_data = &bytes[at + 4..at + 2 + length];
            if marker == 0xE1 && segment_data.starts_with(EXIF_HEADER) {
                let tiff_at = at + 4 + EXIF_HEADER.len();
                segment.children = exif_fields(&bytes[tiff_at..at + 2 + length], base + tiff_at);
                exif_tags += segment.children.len().saturating_sub(1);
                segment.value = format!("{length} bytes, EXIF");
            }
            segments.push(segment);
            at += 2 + length;
            if marker == 0xDA {
                // Entropy-coded data follows until the next real marker.
                let scan_start = at;
                while at + 1 < bytes.len() && at < MAX_EXTENT {
                    if bytes[at] == 0xFF && bytes[at + 1] != 0x00 && !(0xD0..=0xD7).contains(&bytes[at + 1]) {
                        break;
                    }
                    at += 1;
                }
                segments.push(Field::new("scan data", base + scan_start, at - scan_start, format!("{} bytes", at - scan_start)));
            }
        }
        let (width, height, precision, components) = dimensions?;
        let detail = format!(
            "JPEG {width}×{height}, {precision}-bit, {components} components, {} segments{}{}",
            segments.len(),
            if exif_tags > 0 { format!(", {exif_tags} EXIF tags") } else { String::new() },
            if complete { "" } else { ", no EOI" }
        );
        Some(
            Finding::new("jpeg", SOURCE, Category::Image, base, at)
                .title("JPEG image")
                .detail(detail)
                .confidence(if complete { 1.0 } else { 0.7 })
                .fields(segments),
        )
    }
}

// ---------------------------------------------------------------------------
// EXIF (a TIFF structure inside a JPEG's APP1 segment)
// ---------------------------------------------------------------------------

const EXIF_HEADER: &[u8] = b"Exif\0\0";
/// Most entries read from one image file directory.
const MAX_IFD_ENTRIES: usize = 512;
const EXIF_IFD_POINTER: u16 = 0x8769;
const GPS_IFD_POINTER: u16 = 0x8825;

/// The tags worth showing, by directory: the camera, the times, and the
/// free text people and apps leave behind.
fn exif_tag_name(directory: ExifDirectory, tag: u16) -> Option<&'static str> {
    match (directory, tag) {
        (ExifDirectory::Image, 0x010E) => Some("ImageDescription"),
        (ExifDirectory::Image, 0x010F) => Some("Make"),
        (ExifDirectory::Image, 0x0110) => Some("Model"),
        (ExifDirectory::Image, 0x0131) => Some("Software"),
        (ExifDirectory::Image, 0x0132) => Some("DateTime"),
        (ExifDirectory::Image, 0x013B) => Some("Artist"),
        (ExifDirectory::Image, 0x8298) => Some("Copyright"),
        (ExifDirectory::Exif, 0x9003) => Some("DateTimeOriginal"),
        (ExifDirectory::Exif, 0x9004) => Some("DateTimeDigitized"),
        (ExifDirectory::Exif, 0x9286) => Some("UserComment"),
        (ExifDirectory::Exif, 0xA420) => Some("ImageUniqueID"),
        (ExifDirectory::Gps, 0x0001) => Some("GPSLatitudeRef"),
        (ExifDirectory::Gps, 0x0002) => Some("GPSLatitude"),
        (ExifDirectory::Gps, 0x0003) => Some("GPSLongitudeRef"),
        (ExifDirectory::Gps, 0x0004) => Some("GPSLongitude"),
        (ExifDirectory::Gps, 0x0006) => Some("GPSAltitude"),
        (ExifDirectory::Gps, 0x001D) => Some("GPSDateStamp"),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExifDirectory {
    Image,
    Exif,
    Gps,
}

/// A TIFF structure's bytes with their byte order.
struct Tiff<'a> {
    bytes: &'a [u8],
    little_endian: bool,
}

impl Tiff<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        if self.little_endian { u16le(self.bytes, at) } else { u16be(self.bytes, at) }
    }

    fn u32(&self, at: usize) -> Option<u32> {
        if self.little_endian { u32le(self.bytes, at) } else { u32be(self.bytes, at) }
    }

    /// The `index`th unsigned rational at `at`.
    fn rational(&self, at: usize, index: usize) -> Option<f64> {
        let numerator = self.u32(at + index * 8)?;
        let denominator = self.u32(at + index * 8 + 4)?;
        (denominator != 0).then(|| f64::from(numerator) / f64::from(denominator))
    }
}

/// One tag's value: where it is in the TIFF bytes, and how long.
struct TagValue {
    tag: u16,
    kind: u16,
    count: usize,
    at: usize,
    len: usize,
}

/// Bytes per value of a TIFF field type.
fn tiff_type_size(kind: u16) -> Option<usize> {
    match kind {
        1 | 2 | 6 | 7 => Some(1),
        3 | 8 => Some(2),
        4 | 9 | 11 | 13 => Some(4),
        5 | 10 | 12 => Some(8),
        _ => None,
    }
}

/// The entries of the directory at `offset`, values located (inline in the
/// entry when they fit in four bytes).
fn ifd_entries(tiff: &Tiff, offset: usize) -> Vec<TagValue> {
    let Some(count) = tiff.u16(offset) else { return Vec::new() };
    (0..usize::from(count).min(MAX_IFD_ENTRIES))
        .filter_map(|index| {
            let entry = offset + 2 + index * 12;
            let tag = tiff.u16(entry)?;
            let kind = tiff.u16(entry + 2)?;
            let count = tiff.u32(entry + 4)? as usize;
            let len = tiff_type_size(kind)?.checked_mul(count)?;
            let at = if len <= 4 { entry + 8 } else { tiff.u32(entry + 8)? as usize };
            tiff.bytes.get(at..at.checked_add(len)?)?;
            Some(TagValue { tag, kind, count, at, len })
        })
        .collect()
}

/// A tag's value as text: ASCII up to its NUL, a UserComment after its
/// 8-byte character code, numbers as numbers, GPS positions in degrees.
fn exif_value_text(tiff: &Tiff, value: &TagValue) -> String {
    let raw = &tiff.bytes[value.at..value.at + value.len];
    match (value.tag, value.kind) {
        (0x9286, _) if raw.len() >= 8 => {
            let (code, text) = raw.split_at(8);
            if code.starts_with(b"UNICODE") {
                let units: Vec<u16> = text.as_chunks::<2>().0.iter().map(|&pair| if tiff.little_endian { u16::from_le_bytes(pair) } else { u16::from_be_bytes(pair) }).collect();
                String::from_utf16_lossy(&units).trim_end_matches('\0').to_string()
            } else {
                String::from_utf8_lossy(text).trim_end_matches(['\0', ' ']).to_string()
            }
        }
        (0x0002 | 0x0004, 5) if value.count == 3 => {
            let parts: Option<Vec<f64>> = (0..3).map(|index| tiff.rational(value.at, index)).collect();
            parts.map_or_else(String::new, |parts| format!("{:.6}°", parts[0] + parts[1] / 60.0 + parts[2] / 3600.0))
        }
        (_, 2) => String::from_utf8_lossy(raw.split(|&byte| byte == 0).next().unwrap_or_default()).into_owned(),
        (_, 3) => tiff.u16(value.at).map(|number| number.to_string()).unwrap_or_default(),
        (_, 4) => tiff.u32(value.at).map(|number| number.to_string()).unwrap_or_default(),
        (_, 5) => tiff.rational(value.at, 0).map(|number| format!("{number}")).unwrap_or_default(),
        _ => super::text_preview(raw, 80),
    }
}

/// The EXIF tags of the TIFF structure in `bytes`, the data of an APP1
/// segment after its "Exif\0\0" header, which starts at document offset
/// `base`. Both byte orders are read; each tag is a field over its value,
/// the image directory's first, then the EXIF and GPS directories'.
fn exif_fields(bytes: &[u8], base: usize) -> Vec<Field> {
    let little_endian = match bytes.get(..4) {
        Some(b"II*\0") => true,
        Some(b"MM\0*") => false,
        _ => return Vec::new(),
    };
    let tiff = Tiff { bytes, little_endian };
    let mut fields = vec![Field::new("byte order", base, 2, if little_endian { "little-endian (II)" } else { "big-endian (MM)" })];
    let Some(first) = tiff.u32(4) else { return fields };
    let mut directories = vec![(ExifDirectory::Image, first as usize)];
    let mut next = 0;
    while let Some(&(directory, offset)) = directories.get(next) {
        next += 1;
        if directories[..next - 1].iter().any(|&(_, earlier)| earlier == offset) {
            continue;
        }
        for value in ifd_entries(&tiff, offset) {
            match (directory, value.tag) {
                (ExifDirectory::Image, EXIF_IFD_POINTER) => directories.extend(tiff.u32(value.at).map(|at| (ExifDirectory::Exif, at as usize))),
                (ExifDirectory::Image, GPS_IFD_POINTER) => directories.extend(tiff.u32(value.at).map(|at| (ExifDirectory::Gps, at as usize))),
                _ => {
                    if let Some(name) = exif_tag_name(directory, value.tag) {
                        fields.push(Field::new(name, base + value.at, value.len, exif_value_text(&tiff, &value)));
                    }
                }
            }
        }
    }
    fields
}

// ---------------------------------------------------------------------------
// GIF
// ---------------------------------------------------------------------------

pub struct GifParser;

/// Skip GIF data sub-blocks starting at `at`; returns the offset after the terminator.
fn gif_skip_sub_blocks(bytes: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let size = *bytes.get(at)? as usize;
        at += 1;
        if size == 0 {
            return Some(at);
        }
        at += size;
        if at > bytes.len() {
            return None;
        }
    }
}

impl Parser for GifParser {
    fn id(&self) -> &str {
        "gif"
    }

    fn name(&self) -> &str {
        "GIF image"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) || bytes.len() < 13 {
            return None;
        }
        let version = String::from_utf8_lossy(&bytes[3..6]).to_string();
        let width = u16le(bytes, 6)?;
        let height = u16le(bytes, 8)?;
        let packed = bytes[10];
        let has_colour_table = packed & 0x80 != 0;
        let colour_table_size = if has_colour_table { 3 * (2usize << (packed & 7)) } else { 0 };
        let mut fields = vec![
            Field::new("header", base, 6, format!("GIF{version}")),
            Field::new("logical screen", base + 6, 7, format!("{width}×{height}")).with_children(vec![
                Field::new("width", base + 6, 2, width.to_string()),
                Field::new("height", base + 8, 2, height.to_string()),
                Field::new("flags", base + 10, 1, format!("{packed:#04x}")),
            ]),
        ];
        let mut at = 13;
        if has_colour_table {
            fields.push(Field::new("global colour table", base + at, colour_table_size, format!("{} entries", colour_table_size / 3)));
            at += colour_table_size;
        }
        let mut frames = 0;
        let mut complete = false;
        while at < bytes.len() && fields.len() < MAX_CHILDREN && at < MAX_EXTENT {
            match bytes[at] {
                0x3B => {
                    fields.push(Field::new("trailer", base + at, 1, "end of GIF"));
                    at += 1;
                    complete = true;
                    break;
                }
                0x21 => {
                    let label = *bytes.get(at + 1)?;
                    let end = gif_skip_sub_blocks(bytes, at + 2)?;
                    fields.push(Field::new(format!("extension {label:#04x}"), base + at, end - at, ""));
                    at = end;
                }
                0x2C => {
                    let local_packed = *bytes.get(at + 9)?;
                    let mut end = at + 10;
                    if local_packed & 0x80 != 0 {
                        end += 3 * (2usize << (local_packed & 7));
                    }
                    end += 1; // LZW minimum code size
                    let end = gif_skip_sub_blocks(bytes, end)?;
                    frames += 1;
                    fields.push(Field::new(format!("image {frames}"), base + at, end - at, format!("{} bytes", end - at)));
                    at = end;
                }
                _ => break,
            }
        }
        Some(
            Finding::new("gif", SOURCE, Category::Image, base, at)
                .title("GIF image")
                .detail(format!("GIF{version} {width}×{height}, {frames} frame(s){}", if complete { "" } else { ", no trailer" }))
                .confidence(if complete { 1.0 } else { 0.7 })
                .fields(fields),
        )
    }
}

// ---------------------------------------------------------------------------
// BMP
// ---------------------------------------------------------------------------

pub struct BmpParser;

impl Parser for BmpParser {
    fn id(&self) -> &str {
        "bmp"
    }

    fn name(&self) -> &str {
        "BMP image"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"BM") && bytes.len() >= 26 && u32le(bytes, 14).is_some_and(|dib| matches!(dib, 12 | 40 | 52 | 56 | 108 | 124))
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let file_size = u32le(bytes, 2)? as usize;
        let pixel_offset = u32le(bytes, 10)?;
        let dib_size = u32le(bytes, 14)?;
        // OS/2 1.x headers (12 bytes) hold the dimensions in 16 bits; later
        // Windows headers in 32. Offsets and sizes follow from that.
        let os2 = dib_size == 12;
        let dimension_len = if os2 { 2 } else { 4 };
        let height_at = 18 + dimension_len;
        let bpp_at = height_at + dimension_len + 2;
        let (width, height, planes, bpp) = if os2 {
            (u16le(bytes, 18)? as i32, u16le(bytes, height_at)? as i32, u16le(bytes, 22)?, u16le(bytes, bpp_at)?)
        } else {
            (u32le(bytes, 18)? as i32, u32le(bytes, height_at)? as i32, u16le(bytes, 26)?, u16le(bytes, bpp_at)?)
        };
        if planes != 1 || !matches!(bpp, 1 | 4 | 8 | 16 | 24 | 32) {
            return None;
        }
        let extent = file_size.clamp(26, bytes.len()).min(MAX_EXTENT);
        let fields = vec![
            Field::new("file header", base, 14, "BM").with_children(vec![
                Field::new("file size", base + 2, 4, file_size.to_string()),
                Field::new("pixel data offset", base + 10, 4, pixel_offset.to_string()),
            ]),
            Field::new("DIB header", base + 14, dib_size as usize, format!("{dib_size} bytes")).with_children(vec![
                Field::new("width", base + 18, dimension_len, width.to_string()),
                Field::new("height", base + height_at, dimension_len, height.to_string()),
                Field::new("bits per pixel", base + bpp_at, 2, bpp.to_string()),
            ]),
        ];
        Some(
            Finding::new("bmp", SOURCE, Category::Image, base, extent)
                .title("BMP image")
                .detail(format!("BMP {width}×{}, {bpp} bpp, {} bytes", height.abs(), file_size))
                .confidence(if file_size <= bytes.len() { 1.0 } else { 0.7 })
                .fields(fields),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, RgbaImage};

    fn encoded(format: ImageFormat) -> Vec<u8> {
        let img = RgbaImage::from_fn(3, 2, |x, y| image::Rgba([x as u8 * 80, y as u8 * 120, 200, 255]));
        let mut out = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(img).write_to(&mut out, format).unwrap();
        out.into_inner()
    }

    #[test]
    fn png_chunks_and_header_are_parsed() {
        let bytes = encoded(ImageFormat::Png);
        let finding = PngParser.parse(&bytes, 500).expect("png");
        assert_eq!(finding.len, bytes.len());
        assert!(finding.detail.starts_with("PNG 3×2"), "{}", finding.detail);
        let chunks = &finding.fields[1].children;
        assert_eq!(chunks[0].name, "IHDR");
        assert_eq!(chunks[0].offset, 508);
        assert_eq!(chunks.last().unwrap().name, "IEND");
        let width = &chunks[0].children[0];
        assert_eq!((width.name.as_str(), width.value.as_str()), ("width", "3"));
    }

    #[test]
    fn jpeg_gif_and_bmp_dimensions_are_parsed() {
        let jpeg = encoded(ImageFormat::Jpeg);
        let finding = JpegParser.parse(&jpeg, 0).expect("jpeg");
        assert!(finding.detail.starts_with("JPEG 3×2"), "{}", finding.detail);
        assert_eq!(finding.len, jpeg.len());

        let gif = encoded(ImageFormat::Gif);
        let finding = GifParser.parse(&gif, 0).expect("gif");
        assert!(finding.detail.contains("3×2"), "{}", finding.detail);
        assert_eq!(finding.len, gif.len());

        let bmp = encoded(ImageFormat::Bmp);
        let finding = BmpParser.parse(&bmp, 0).expect("bmp");
        assert!(finding.detail.starts_with("BMP 3×2"), "{}", finding.detail);
        assert_eq!(finding.len, bmp.len());
    }

    /// A TIFF structure as a phone writes into APP1: an image directory with
    /// text tags and pointers to an EXIF and a GPS directory.
    fn exif_tiff(little_endian: bool) -> Vec<u8> {
        let u16_bytes = |value: u16| if little_endian { value.to_le_bytes() } else { value.to_be_bytes() };
        let u32_bytes = |value: u32| if little_endian { value.to_le_bytes() } else { value.to_be_bytes() };
        // Each directory: (tag, type, count, value bytes); values over four bytes go after it.
        type Tag = (u16, u16, u32, Vec<u8>);
        let ascii = |text: &str| -> (u16, u32, Vec<u8>) { (2, text.len() as u32 + 1, [text.as_bytes(), b"\0"].concat()) };
        let mut out = Vec::new();
        out.extend_from_slice(if little_endian { b"II*\0" } else { b"MM\0*" });
        out.extend_from_slice(&u32_bytes(8));
        let write_directory = |out: &mut Vec<u8>, tags: Vec<Tag>| {
            let start = out.len();
            let mut extra_at = start + 2 + tags.len() * 12 + 4;
            let mut extra = Vec::new();
            out.extend_from_slice(&u16_bytes(tags.len() as u16));
            for (tag, kind, count, value) in tags {
                out.extend_from_slice(&u16_bytes(tag));
                out.extend_from_slice(&u16_bytes(kind));
                out.extend_from_slice(&u32_bytes(count));
                if value.len() <= 4 {
                    let mut inline = value.clone();
                    inline.resize(4, 0);
                    out.extend_from_slice(&inline);
                } else {
                    out.extend_from_slice(&u32_bytes(extra_at as u32));
                    extra.extend_from_slice(&value);
                    extra_at += value.len();
                }
            }
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&extra);
        };
        let pointer = |value: u32| u32_bytes(value).to_vec();
        let (make_type, make_count, make) = ascii("Google");
        let (description_type, description_count, description) = ascii("reminder - backup.zip password: Kestrel!Moor42");
        let (time_type, time_count, time) = ascii("2026:09:12 08:14:54");
        let comment = [b"ASCII\0\0\0".as_slice(), b"yellow note\0\0\0\0\0"].concat();
        // Each directory is a count, 12 bytes a tag and a next link, then its long values.
        let exif_at = 8 + 2 + 4 * 12 + 4 + make.len() + description.len();
        let gps_at = exif_at + 2 + 2 * 12 + 4 + time.len() + comment.len();
        write_directory(&mut out, vec![
            (0x010E, description_type, description_count, description),
            (0x010F, make_type, make_count, make),
            // Pillow writes the pointers with the IFD type (13), others as LONG (4).
            (EXIF_IFD_POINTER, if little_endian { 4 } else { 13 }, 1, pointer(exif_at as u32)),
            (GPS_IFD_POINTER, 4, 1, pointer(gps_at as u32)),
        ]);
        assert_eq!(out.len(), exif_at);
        write_directory(&mut out, vec![(0x9003, time_type, time_count, time), (0x9286, 7, comment.len() as u32, comment)]);
        assert_eq!(out.len(), gps_at);
        let latitude: Vec<u8> = [(51u32, 1u32), (30, 1), (36, 1)].iter().flat_map(|&(numerator, denominator)| [u32_bytes(numerator), u32_bytes(denominator)].concat()).collect();
        write_directory(&mut out, vec![(0x0001, 2, 2, b"N\0".to_vec()), (0x0002, 5, 3, latitude)]);
        out
    }

    fn jpeg_with_exif(tiff: &[u8]) -> Vec<u8> {
        let plain = encoded(ImageFormat::Jpeg);
        let mut app1 = vec![0xFF, 0xE1];
        app1.extend_from_slice(&((2 + EXIF_HEADER.len() + tiff.len()) as u16).to_be_bytes());
        app1.extend_from_slice(EXIF_HEADER);
        app1.extend_from_slice(tiff);
        [&plain[..2], &app1, &plain[2..]].concat()
    }

    #[test]
    fn exif_tags_in_a_jpeg_are_fields_whichever_the_byte_order() {
        for little_endian in [true, false] {
            let jpeg = jpeg_with_exif(&exif_tiff(little_endian));
            let finding = JpegParser.parse(&jpeg, 100).expect("jpeg");
            let app1 = finding.fields.iter().find(|field| field.name == "APP1").expect("APP1");
            let tag = |name: &str| app1.children.iter().find(|field| field.name == name).unwrap_or_else(|| panic!("no {name}: {:#?}", app1.children));
            let description = tag("ImageDescription");
            assert_eq!(description.value, "reminder - backup.zip password: Kestrel!Moor42");
            let description_at = description.offset - 100;
            assert_eq!(&jpeg[description_at..description_at + 8], b"reminder", "the field covers the text itself");
            assert_eq!(tag("Make").value, "Google");
            assert_eq!(tag("DateTimeOriginal").value, "2026:09:12 08:14:54");
            assert_eq!(tag("UserComment").value, "yellow note");
            assert_eq!(tag("GPSLatitudeRef").value, "N");
            assert_eq!(tag("GPSLatitude").value, "51.510000°");
            assert!(finding.detail.contains("6 EXIF tags"), "{}", finding.detail);
            assert!(finding.detail.starts_with("JPEG 3×2"), "the image is still read: {}", finding.detail);
        }
    }

    #[test]
    fn a_damaged_exif_block_does_not_panic() {
        let tiff = exif_tiff(true);
        for cut in [0, 3, 8, 20, 60, tiff.len() - 1] {
            let _ = JpegParser.parse(&jpeg_with_exif(&tiff[..cut]), 0);
        }
        let mut looping = tiff.clone();
        looping[4..8].copy_from_slice(&8u32.to_le_bytes());
        let _ = JpegParser.parse(&jpeg_with_exif(&looping), 0);
    }

    #[test]
    fn an_os2_bitmap_labels_its_16_bit_dimensions_and_bit_depth_where_they_are() {
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&38u32.to_le_bytes()); // file size
        bmp.extend_from_slice(&[0; 4]);
        bmp.extend_from_slice(&26u32.to_le_bytes()); // pixel data offset
        bmp.extend_from_slice(&12u32.to_le_bytes()); // OS/2 1.x header
        bmp.extend_from_slice(&3u16.to_le_bytes()); // width
        bmp.extend_from_slice(&2u16.to_le_bytes()); // height
        bmp.extend_from_slice(&1u16.to_le_bytes()); // planes
        bmp.extend_from_slice(&24u16.to_le_bytes()); // bits per pixel
        bmp.extend_from_slice(&[0; 12]);
        let finding = BmpParser.parse(&bmp, 0).expect("OS/2 bmp");
        let header = &finding.fields[1].children;
        let placed: Vec<(&str, usize, usize, &str)> = header.iter().map(|f| (f.name.as_str(), f.offset, f.len, f.value.as_str())).collect();
        assert_eq!(placed, [("width", 18, 2, "3"), ("height", 20, 2, "2"), ("bits per pixel", 24, 2, "24")]);
    }

    #[test]
    fn preview_decodes_and_downscales() {
        let bytes = encoded(ImageFormat::Png);
        let preview = image_preview(&bytes, 64).expect("preview");
        assert_eq!((preview.width, preview.height), (3, 2));
        assert_eq!(preview.rgba.len(), 3 * 2 * 4);
        assert!(image_preview(b"not an image", 64).is_none());
    }
}
