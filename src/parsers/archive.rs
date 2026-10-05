//! Archive containers walked by hand: ZIP local headers, ustar TAR, ar and
//! newc cpio.

use super::{MAX_CHILDREN, MAX_EXTENT, fixed_string, human_bytes, text_preview, u16le, u32le};
use crate::plugin::{Category, Field, Finding, Parser};

const SOURCE: &str = "parsers.archive";

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

pub struct ZipParser;

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
const ZIP_END: &[u8] = b"PK\x05\x06";

fn zip_method_name(method: u16) -> String {
    match method {
        0 => "stored".to_string(),
        8 => "deflate".to_string(),
        9 => "deflate64".to_string(),
        12 => "bzip2".to_string(),
        14 => "lzma".to_string(),
        93 => "zstd".to_string(),
        95 => "xz".to_string(),
        99 => "AES".to_string(),
        other => format!("method {other}"),
    }
}

impl Parser for ZipParser {
    fn id(&self) -> &str {
        "zip"
    }

    fn name(&self) -> &str {
        "ZIP archive"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(ZIP_LOCAL)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !bytes.starts_with(ZIP_LOCAL) {
            return None;
        }
        let mut entries = Vec::new();
        let mut at = 0;
        let mut total_uncompressed = 0u64;
        let mut unknown_sizes = false;
        while bytes.get(at..at + 4) == Some(ZIP_LOCAL) && entries.len() < MAX_CHILDREN {
            if at + 30 > bytes.len() {
                break;
            }
            let flags = u16le(bytes, at + 6)?;
            let method = u16le(bytes, at + 8)?;
            let crc = u32le(bytes, at + 14)?;
            let compressed = u32le(bytes, at + 18)? as usize;
            let uncompressed = u32le(bytes, at + 22)? as usize;
            let name_len = u16le(bytes, at + 26)? as usize;
            let extra_len = u16le(bytes, at + 28)? as usize;
            let name_start = at + 30;
            let name = text_preview(bytes.get(name_start..name_start + name_len)?, 80);
            let data_start = name_start + name_len + extra_len;
            let uses_descriptor = flags & 0x08 != 0 && compressed == 0;
            let entry_len = 30 + name_len + extra_len + compressed;
            entries.push(
                Field::new(
                    name,
                    base + at,
                    entry_len,
                    format!(
                        "{}, {} → {}, crc {crc:08x}",
                        zip_method_name(method),
                        human_bytes(compressed as u64),
                        human_bytes(uncompressed as u64)
                    ),
                )
                .with_children(vec![
                    Field::new("method", base + at + 8, 2, zip_method_name(method)),
                    Field::new("compressed size", base + at + 18, 4, compressed.to_string()),
                    Field::new("uncompressed size", base + at + 22, 4, uncompressed.to_string()),
                    Field::new("data", base + data_start, compressed, format!("{compressed} bytes")),
                ]),
            );
            total_uncompressed += uncompressed as u64;
            if uses_descriptor {
                // The sizes live in a data descriptor after the data; without
                // the central directory we cannot know where that is.
                unknown_sizes = true;
                break;
            }
            at = data_start + compressed;
            if at > bytes.len() || at > MAX_EXTENT {
                break;
            }
        }
        if entries.is_empty() {
            return None;
        }
        let mut extent = at.min(bytes.len());
        let mut complete = false;
        let mut central_entries = 0;
        if !unknown_sizes {
            while bytes.get(at..at + 4) == Some(ZIP_CENTRAL) && at + 46 <= bytes.len() {
                let name_len = u16le(bytes, at + 28)? as usize;
                let extra_len = u16le(bytes, at + 30)? as usize;
                let comment_len = u16le(bytes, at + 32)? as usize;
                at += 46 + name_len + extra_len + comment_len;
                central_entries += 1;
                if at > bytes.len() {
                    break;
                }
            }
            if bytes.get(at..at + 4) == Some(ZIP_END) && at + 22 <= bytes.len() {
                let comment_len = u16le(bytes, at + 20)? as usize;
                at += 22 + comment_len;
                extent = at.min(bytes.len());
                complete = true;
            }
        }
        let count = entries.len();
        let fields = vec![Field::new("entries", base, extent, format!("{count} entries")).with_children(entries)];
        let detail = format!(
            "ZIP with {count} local entries, {} uncompressed{}",
            human_bytes(total_uncompressed),
            if complete {
                format!(", central directory of {central_entries}")
            } else if unknown_sizes {
                ", sizes in data descriptors".to_string()
            } else {
                ", no end record".to_string()
            }
        );
        Some(
            Finding::new("zip", SOURCE, Category::Archive, base, extent)
                .title("ZIP archive")
                .detail(detail)
                .confidence(if complete { 1.0 } else { 0.7 })
                .fields(fields),
        )
    }
}

// ---------------------------------------------------------------------------
// TAR (ustar)
// ---------------------------------------------------------------------------

pub struct TarParser;

const TAR_BLOCK: usize = 512;

fn parse_octal(field: &[u8]) -> Option<u64> {
    let text = fixed_string(field);
    let text = text.trim();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

fn tar_type_name(flag: u8) -> &'static str {
    match flag {
        b'0' | 0 => "file",
        b'1' => "hard link",
        b'2' => "symlink",
        b'3' => "character device",
        b'4' => "block device",
        b'5' => "directory",
        b'6' => "fifo",
        b'L' => "long name",
        b'x' | b'g' => "pax header",
        _ => "other",
    }
}

impl Parser for TarParser {
    fn id(&self) -> &str {
        "tar"
    }

    fn name(&self) -> &str {
        "tar archive"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.len() >= TAR_BLOCK && &bytes[257..262] == b"ustar"
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let mut entries = Vec::new();
        let mut at = 0;
        let mut complete = false;
        while at + TAR_BLOCK <= bytes.len() && entries.len() < MAX_CHILDREN && at < MAX_EXTENT {
            let block = &bytes[at..at + TAR_BLOCK];
            if block.iter().all(|&b| b == 0) {
                // Two zero blocks end the archive; one is close enough.
                at += TAR_BLOCK;
                if bytes.get(at..at + TAR_BLOCK).is_some_and(|next| next.iter().all(|&b| b == 0)) {
                    at += TAR_BLOCK;
                }
                complete = true;
                break;
            }
            if &block[257..262] != b"ustar" {
                break;
            }
            let name = fixed_string(&block[0..100]);
            let size = parse_octal(&block[124..136])? as usize;
            let kind = tar_type_name(block[156]);
            let data_blocks = size.div_ceil(TAR_BLOCK);
            let entry_len = TAR_BLOCK + data_blocks * TAR_BLOCK;
            entries.push(
                Field::new(name, base + at, entry_len, format!("{kind}, {}", human_bytes(size as u64))).with_children(vec![
                    Field::new("header", base + at, TAR_BLOCK, kind),
                    Field::new("data", base + at + TAR_BLOCK, size, format!("{size} bytes")),
                ]),
            );
            at += entry_len;
        }
        if entries.is_empty() {
            return None;
        }
        let extent = at.min(bytes.len());
        let count = entries.len();
        Some(
            Finding::new("tar", SOURCE, Category::Archive, base, extent)
                .title("tar archive")
                .detail(format!("ustar archive with {count} entries{}", if complete { "" } else { ", no end blocks" }))
                .confidence(if complete { 1.0 } else { 0.7 })
                .fields(vec![Field::new("entries", base, extent, format!("{count} entries")).with_children(entries)]),
        )
    }
}

// ---------------------------------------------------------------------------
// ar
// ---------------------------------------------------------------------------

pub struct ArParser;

const AR_MAGIC: &[u8] = b"!<arch>\n";

impl Parser for ArParser {
    fn id(&self) -> &str {
        "ar"
    }

    fn name(&self) -> &str {
        "ar archive"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(AR_MAGIC)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !bytes.starts_with(AR_MAGIC) {
            return None;
        }
        let mut members = Vec::new();
        let mut at = AR_MAGIC.len();
        while at + 60 <= bytes.len() && members.len() < MAX_CHILDREN && at < MAX_EXTENT {
            let header = &bytes[at..at + 60];
            if &header[58..60] != b"`\n" {
                break;
            }
            let name = String::from_utf8_lossy(&header[0..16]).trim_end().to_string();
            let size: usize = String::from_utf8_lossy(&header[48..58]).trim().parse().ok()?;
            members.push(Field::new(name, base + at, 60 + size, format!("{} bytes", size)));
            at += 60 + size + (size & 1);
        }
        if members.is_empty() {
            return None;
        }
        let extent = at.min(bytes.len());
        let count = members.len();
        Some(
            Finding::new("ar", SOURCE, Category::Archive, base, extent)
                .title("ar archive")
                .detail(format!("ar archive with {count} members"))
                .fields(vec![Field::new("members", base + 8, extent - 8, format!("{count} members")).with_children(members)]),
        )
    }
}

// ---------------------------------------------------------------------------
// cpio (newc)
// ---------------------------------------------------------------------------

pub struct CpioParser;

const CPIO_NEWC: &[u8] = b"070701";

fn hex_field(bytes: &[u8], at: usize) -> Option<usize> {
    let text = std::str::from_utf8(bytes.get(at..at + 8)?).ok()?;
    usize::from_str_radix(text, 16).ok()
}

impl Parser for CpioParser {
    fn id(&self) -> &str {
        "cpio"
    }

    fn name(&self) -> &str {
        "cpio archive"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(CPIO_NEWC) || bytes.starts_with(b"070702")
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let mut entries = Vec::new();
        let mut at = 0;
        let mut complete = false;
        while at + 110 <= bytes.len() && entries.len() < MAX_CHILDREN && at < MAX_EXTENT {
            if !(bytes[at..].starts_with(CPIO_NEWC) || bytes[at..].starts_with(b"070702")) {
                break;
            }
            let file_size = hex_field(bytes, at + 54)?;
            let name_size = hex_field(bytes, at + 94)?;
            let name = fixed_string(bytes.get(at + 110..at + 110 + name_size)?);
            let header_len = (110 + name_size).div_ceil(4) * 4;
            let entry_len = header_len + file_size.div_ceil(4) * 4;
            let is_trailer = name == "TRAILER!!!";
            entries.push(Field::new(name, base + at, entry_len, format!("{} bytes", file_size)));
            at += entry_len;
            if is_trailer {
                complete = true;
                break;
            }
        }
        if entries.is_empty() {
            return None;
        }
        let extent = at.min(bytes.len());
        let count = entries.len();
        Some(
            Finding::new("cpio", SOURCE, Category::Archive, base, extent)
                .title("cpio archive")
                .detail(format!("cpio (newc) archive with {count} entries{}", if complete { "" } else { ", no trailer" }))
                .confidence(if complete { 1.0 } else { 0.7 })
                .fields(vec![Field::new("entries", base, extent, format!("{count} entries")).with_children(entries)]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }

    fn zip_with_one_stored_entry(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let crc = crc32(data);
        out.extend_from_slice(ZIP_LOCAL);
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&[0, 0, 0, 0]); // time, date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(data);
        let central_at = out.len();
        out.extend_from_slice(ZIP_CENTRAL);
        out.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name);
        let central_len = out.len() - central_at;
        out.extend_from_slice(ZIP_END);
        out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        out.extend_from_slice(&(central_len as u32).to_le_bytes());
        out.extend_from_slice(&(central_at as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn tar_with_one_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|&b| b as u32).sum::<u32>() + 8 * 32;
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut out = header;
        out.extend_from_slice(data);
        out.resize(512 + data.len().div_ceil(512) * 512, 0);
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    #[test]
    fn zip_entries_and_end_record_are_parsed() {
        let bytes = zip_with_one_stored_entry(b"hello.txt", b"hello zip world");
        let finding = ZipParser.parse(&bytes, 10).expect("zip");
        assert_eq!(finding.len, bytes.len());
        assert_eq!(finding.confidence, 1.0);
        let entry = &finding.fields[0].children[0];
        assert_eq!(entry.name, "hello.txt");
        assert!(entry.value.starts_with("stored"), "{}", entry.value);
        assert_eq!(entry.offset, 10);
        assert!(finding.detail.contains("1 local entries"), "{}", finding.detail);
    }

    #[test]
    fn tar_entries_are_walked_to_the_end_blocks() {
        let bytes = tar_with_one_entry("dir/file.bin", &[7u8; 700]);
        assert!(TarParser.looks_like(&bytes));
        let finding = TarParser.parse(&bytes, 0).expect("tar");
        assert_eq!(finding.len, bytes.len());
        let entry = &finding.fields[0].children[0];
        assert_eq!(entry.name, "dir/file.bin");
        assert_eq!(entry.len, 512 + 1024);
        assert_eq!(entry.children[1].len, 700);
    }

    #[test]
    fn ar_and_cpio_members_are_listed() {
        let mut ar = AR_MAGIC.to_vec();
        ar.extend_from_slice(format!("{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", "a.o/", "0", "0", "0", "644", "5").as_bytes());
        ar.extend_from_slice(b"hello\0");
        let finding = ArParser.parse(&ar, 0).expect("ar");
        assert_eq!(finding.fields[0].children[0].name, "a.o/");
        assert_eq!(finding.len, ar.len());

        let mut cpio = Vec::new();
        for (name, data) in [("file", b"data" as &[u8]), ("TRAILER!!!", b"")] {
            let mut header = format!("070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}", 1, 0o100644, 0, 0, 1, 0, data.len(), 0, 0, 0, 0, name.len() + 1, 0).into_bytes();
            header.extend_from_slice(name.as_bytes());
            header.push(0);
            while header.len() % 4 != 0 {
                header.push(0);
            }
            header.extend_from_slice(data);
            while header.len() % 4 != 0 {
                header.push(0);
            }
            cpio.extend_from_slice(&header);
        }
        let finding = CpioParser.parse(&cpio, 0).expect("cpio");
        assert_eq!(finding.fields[0].children.len(), 2);
        assert_eq!(finding.confidence, 1.0);
        assert_eq!(finding.len, cpio.len());
    }
}
