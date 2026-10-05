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
            "JPEG {width}×{height}, {precision}-bit, {components} components, {} segments{}",
            segments.len(),
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
        let (width, height, planes, bpp) = if dib_size == 12 {
            (u16le(bytes, 18)? as i32, u16le(bytes, 20)? as i32, u16le(bytes, 22)?, u16le(bytes, 24)?)
        } else {
            (u32le(bytes, 18)? as i32, u32le(bytes, 22)? as i32, u16le(bytes, 26)?, u16le(bytes, 28)?)
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
                Field::new("width", base + 18, 4, width.to_string()),
                Field::new("height", base + 22, 4, height.to_string()),
                Field::new("bits per pixel", base + 28, 2, bpp.to_string()),
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

    #[test]
    fn preview_decodes_and_downscales() {
        let bytes = encoded(ImageFormat::Png);
        let preview = image_preview(&bytes, 64).expect("preview");
        assert_eq!((preview.width, preview.height), (3, 2));
        assert_eq!(preview.rgba.len(), 3 * 2 * 4);
        assert!(image_preview(b"not an image", 64).is_none());
    }
}
