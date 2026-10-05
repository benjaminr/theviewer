//! Imports Apache Tika's mimetypes database into `catalog/tika.toml`.
//!
//! Usage: `cargo run --bin import_catalog -- path/to/tika-mimetypes.xml [out.toml]`
//!
//! Tika's `<match>` elements map onto the catalogue model as follows: every
//! top-level match inside a `<magic>` is one alternative; nested matches
//! become `children` (at least one must hold). Regex matches are dropped,
//! and entries left with no usable magic are not emitted.

use std::path::PathBuf;

use theviewer::catalog::{Alternative, CatalogFile, MatchDef, OffsetDef, SignatureDef, to_hex};

const LICENCE_NOTE: &str = "# Generated from Apache Tika's tika-mimetypes.xml by `cargo run --bin import_catalog`.\n\
# Source: https://github.com/apache/tika (Apache License 2.0; see catalog/LICENSE-tika.txt).\n\
# Do not edit by hand; regenerate instead. Hand-written entries live in curated.toml.\n\n";

/// Counts gathered during an import.
pub struct Report {
    imported: usize,
    no_magic: usize,
    regex_only: usize,
    regex_children_dropped: usize,
    unsupported_type: usize,
}

pub fn main() {
    let mut args = std::env::args().skip(1);
    let Some(input) = args.next() else {
        eprintln!("usage: import_catalog <tika-mimetypes.xml> [catalog/tika.toml]");
        std::process::exit(2);
    };
    let output = args.next().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("catalog/tika.toml"));

    let xml = std::fs::read_to_string(&input).unwrap_or_else(|e| {
        eprintln!("cannot read {input}: {e}");
        std::process::exit(1);
    });
    let (file, report) = convert(&xml).unwrap_or_else(|e| {
        eprintln!("cannot parse {input}: {e}");
        std::process::exit(1);
    });
    let body = toml::to_string(&file).unwrap_or_else(|e| {
        eprintln!("cannot serialise: {e}");
        std::process::exit(1);
    });
    std::fs::write(&output, format!("{LICENCE_NOTE}{body}")).unwrap_or_else(|e| {
        eprintln!("cannot write {}: {e}", output.display());
        std::process::exit(1);
    });
    println!(
        "imported {} entries to {}; dropped {} with no magic, {} with regex-only magic, {} unsupported match types; {} regex children dropped",
        report.imported,
        output.display(),
        report.no_magic,
        report.regex_only,
        report.unsupported_type,
        report.regex_children_dropped
    );
}

/// Convert the whole XML document.
pub fn convert(xml: &str) -> Result<(CatalogFile, Report), String> {
    let document = roxmltree::Document::parse(xml).map_err(|e| e.to_string())?;
    let mut file = CatalogFile::default();
    let mut report = Report { imported: 0, no_magic: 0, regex_only: 0, regex_children_dropped: 0, unsupported_type: 0 };

    for node in document.descendants().filter(|n| n.has_tag_name("mime-type")) {
        let Some(mime) = node.attribute("type") else { continue };
        let acronym = child_text(&node, "acronym");
        let comment = child_text(&node, "_comment");
        let extensions: Vec<String> = node
            .children()
            .filter(|n| n.has_tag_name("glob"))
            .filter_map(|n| n.attribute("pattern"))
            .filter_map(|pattern| pattern.strip_prefix("*.").map(|ext| ext.to_ascii_lowercase()))
            .collect();
        let references: Vec<String> = node
            .children()
            .filter(|n| n.has_tag_name("sub-class-of"))
            .filter_map(|n| n.attribute("type"))
            .map(|parent| format!("sub-class-of:{parent}"))
            .collect();

        let mut magic = Vec::new();
        let mut priority = 50;
        let mut had_magic = false;
        let mut had_regex = false;
        for magic_node in node.children().filter(|n| n.has_tag_name("magic")) {
            had_magic = true;
            priority = magic_node.attribute("priority").and_then(|p| p.parse().ok()).unwrap_or(50);
            for match_node in magic_node.children().filter(|n| n.has_tag_name("match")) {
                match convert_match(&match_node, &mut report) {
                    Ok(Some(def)) => magic.push(Alternative { matches: vec![def] }),
                    Ok(None) => had_regex = true,
                    Err(()) => report.unsupported_type += 1,
                }
            }
        }
        if !had_magic {
            report.no_magic += 1;
            continue;
        }
        if magic.is_empty() {
            if had_regex {
                report.regex_only += 1;
            } else {
                report.no_magic += 1;
            }
            continue;
        }

        file.signatures.push(SignatureDef {
            id: mime.to_string(),
            name: display_name(mime, acronym.as_deref(), comment.as_deref()),
            category: category_for(mime).to_string(),
            mime: Some(mime.to_string()),
            extensions,
            priority,
            references,
            confidence: None,
            magic,
            extent: None,
        });
        report.imported += 1;
    }
    Ok((file, report))
}

fn child_text(node: &roxmltree::Node, tag: &str) -> Option<String> {
    node.children().find(|n| n.has_tag_name(tag)).and_then(|n| n.text()).map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
}

/// "PNG image (Portable Network Graphics)" style names.
fn display_name(mime: &str, acronym: Option<&str>, comment: Option<&str>) -> String {
    let kind = match mime.split('/').next().unwrap_or("") {
        "audio" => Some("audio"),
        "video" => Some("video"),
        _ => None,
    };
    let base = match (acronym, comment) {
        (Some(acronym), Some(comment)) if comment.to_lowercase().contains(&acronym.to_lowercase()) => comment.to_string(),
        (Some(acronym), Some(comment)) => format!("{acronym} ({comment})"),
        (Some(acronym), None) => acronym.to_string(),
        (None, Some(comment)) => comment.to_string(),
        (None, None) => mime.split('/').nth(1).unwrap_or(mime).trim_start_matches("x-").trim_start_matches("vnd.").to_string(),
    };
    match kind {
        Some(kind) if !base.to_lowercase().contains(kind) => format!("{base} {kind}"),
        _ => base,
    }
}

fn category_for(mime: &str) -> &'static str {
    let (top, sub) = mime.split_once('/').unwrap_or((mime, ""));
    let sub = sub.to_ascii_lowercase();
    if top == "image" {
        return "Image";
    }
    const EXECUTABLE: [&str; 12] = [
        "x-executable",
        "x-sharedlib",
        "x-mach-binary",
        "vnd.microsoft.portable-executable",
        "x-elf",
        "x-object",
        "x-coredump",
        "wasm",
        "java-vm",
        "x-dex",
        "x-msdownload",
        "x-dosexec",
    ];
    const ARCHIVE: [&str; 16] = [
        "zip",
        "x-tar",
        "x-7z-compressed",
        "x-rar-compressed",
        "vnd.rar",
        "x-archive",
        "x-cpio",
        "x-iso9660-image",
        "x-arj",
        "x-lha",
        "x-lzh-compressed",
        "x-ace-compressed",
        "x-stuffit",
        "vnd.ms-cab-compressed",
        "x-xar",
        "x-rpm",
    ];
    const FILESYSTEM: [&str; 6] = ["x-apple-diskimage", "x-raw-disk-image", "x-qemu-disk", "x-vhd", "x-vmdk", "x-virtualbox-vdi"];
    const DOCUMENT_HINTS: [&str; 9] = ["pdf", "msword", "openxmlformats", "oasis.opendocument", "rtf", "postscript", "epub", "vnd.ms-", "x-mobipocket"];
    if top == "application" {
        if EXECUTABLE.contains(&sub.as_str()) {
            return "Executable";
        }
        if ARCHIVE.contains(&sub.as_str()) {
            return "Archive";
        }
        if FILESYSTEM.contains(&sub.as_str()) || sub.contains("disk-image") || sub.contains("filesystem") {
            return "Filesystem";
        }
        if DOCUMENT_HINTS.iter().any(|hint| sub.contains(hint)) {
            return "Document";
        }
    }
    if top == "text" {
        return "Document";
    }
    "Signature"
}

/// Convert one `<match>`. `Ok(None)` means it was a regex and was dropped.
fn convert_match(node: &roxmltree::Node, report: &mut Report) -> Result<Option<MatchDef>, ()> {
    let kind = node.attribute("type").unwrap_or("string");
    if kind == "regex" {
        return Ok(None);
    }
    let value = node.attribute("value").ok_or(())?;
    let offset = parse_offset(node.attribute("offset").unwrap_or("0")).ok_or(())?;
    let (bytes, ignore_case) = match kind {
        "string" => (parse_string_value(value).ok_or(())?, false),
        "stringignorecase" => (parse_string_value(value).ok_or(())?, true),
        "unicodeLE" => (value.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect(), false),
        "byte" => (parse_numeric(value, 1, true).ok_or(())?, false),
        "big16" => (parse_numeric(value, 2, true).ok_or(())?, false),
        "big32" => (parse_numeric(value, 4, true).ok_or(())?, false),
        "little16" | "host16" => (parse_numeric(value, 2, false).ok_or(())?, false),
        "little32" | "host32" => (parse_numeric(value, 4, false).ok_or(())?, false),
        _ => return Err(()),
    };
    let mask = match node.attribute("mask") {
        None => None,
        Some(mask) => {
            let mut mask_bytes = match kind {
                "string" | "stringignorecase" | "unicodeLE" => parse_string_value(mask).ok_or(())?,
                "byte" => parse_numeric(mask, 1, true).ok_or(())?,
                "big16" => parse_numeric(mask, 2, true).ok_or(())?,
                "big32" => parse_numeric(mask, 4, true).ok_or(())?,
                _ => parse_numeric(mask, if kind.ends_with("16") { 2 } else { 4 }, false).ok_or(())?,
            };
            mask_bytes.resize(bytes.len(), 0xFF);
            if mask_bytes.iter().all(|&m| m == 0xFF) { None } else { Some(to_hex(&mask_bytes)) }
        }
    };
    if bytes.is_empty() {
        return Err(());
    }

    let mut children = Vec::new();
    for child in node.children().filter(|n| n.has_tag_name("match")) {
        match convert_match(&child, report) {
            Ok(Some(def)) => children.push(def),
            Ok(None) => report.regex_children_dropped += 1,
            Err(()) => report.unsupported_type += 1,
        }
    }

    Ok(Some(MatchDef {
        offset,
        bytes: Some(to_hex(&bytes)),
        string: None,
        mask,
        kind: theviewer::catalog::MatchKind::Bytes,
        ignore_case,
        pointer: None,
        children,
    }))
}

fn parse_offset(text: &str) -> Option<OffsetDef> {
    if let Some((start, end)) = text.split_once(':') {
        Some(OffsetDef { start: start.trim().parse().ok()?, end: end.trim().parse().ok()? })
    } else {
        Some(OffsetDef::fixed(text.trim().parse().ok()?))
    }
}

/// Tika string values: `0x` hex, or text with `\xHH`, `\ooo` and C escapes.
pub fn parse_string_value(value: &str) -> Option<Vec<u8>> {
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        return theviewer::catalog::parse_hex(hex).ok();
    }
    let mut out = Vec::with_capacity(value.len());
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' {
            let mut buffer = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            i += 1;
            continue;
        }
        i += 1;
        let Some(&escape) = chars.get(i) else {
            out.push(b'\\');
            break;
        };
        match escape {
            'x' => {
                let hex: String = chars[i + 1..].iter().take(2).collect();
                let byte = u8::from_str_radix(&hex, 16).ok()?;
                out.push(byte);
                i += 1 + hex.len();
            }
            '0'..='7' => {
                let octal: String = chars[i..].iter().take(3).take_while(|c| ('0'..='7').contains(*c)).collect();
                let byte = u8::from_str_radix(&octal, 8).ok()?;
                out.push(byte);
                i += octal.len();
            }
            'n' => {
                out.push(b'\n');
                i += 1;
            }
            'r' => {
                out.push(b'\r');
                i += 1;
            }
            't' => {
                out.push(b'\t');
                i += 1;
            }
            '\\' => {
                out.push(b'\\');
                i += 1;
            }
            ' ' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(b'\\');
                let mut buffer = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
                i += 1;
            }
        }
    }
    Some(out)
}

/// Numeric match values become fixed-width bytes.
pub fn parse_numeric(value: &str, width: usize, big_endian: bool) -> Option<Vec<u8>> {
    let value = value.trim();
    let number: u64 = if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        value.parse().ok()?
    };
    let bytes = number.to_be_bytes();
    let slice = &bytes[8 - width..];
    Some(if big_endian { slice.to_vec() } else { slice.iter().rev().copied().collect() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_values_decode_hex_escapes_and_octal() {
        assert_eq!(parse_string_value("0x89504e47").unwrap(), vec![0x89, 0x50, 0x4e, 0x47]);
        assert_eq!(parse_string_value("\\x89PNG\\r\\n").unwrap(), b"\x89PNG\r\n");
        assert_eq!(parse_string_value("PK\\003\\004").unwrap(), b"PK\x03\x04");
        assert_eq!(parse_numeric("0x1a45dfa3", 4, true).unwrap(), vec![0x1a, 0x45, 0xdf, 0xa3]);
        assert_eq!(parse_numeric("0xCAFEBABE", 4, false).unwrap(), vec![0xbe, 0xba, 0xfe, 0xca]);
    }

    #[test]
    fn masks_and_nested_matches_convert() {
        let xml = r#"<mime-info><mime-type type="application/x-test">
            <magic priority="60">
              <match value="0x060B2A86" mask="0xFFFFFF00" type="string" offset="2:6">
                <match value="ABC" type="string" offset="20"/>
                <match value="x" type="regex" offset="0"/>
              </match>
            </magic>
            <glob pattern="*.tst"/>
          </mime-type>
          <mime-type type="application/x-nomagic"><glob pattern="*.nm"/></mime-type>
          </mime-info>"#;
        let (file, report) = convert(xml).unwrap();
        assert_eq!(file.signatures.len(), 1);
        let def = &file.signatures[0];
        assert_eq!(def.priority, 60);
        assert_eq!(def.extensions, vec!["tst"]);
        let m = &def.magic[0].matches[0];
        assert_eq!(m.offset, OffsetDef { start: 2, end: 6 });
        assert_eq!(m.bytes.as_deref(), Some("060b2a86"));
        assert_eq!(m.mask.as_deref(), Some("ffffff00"));
        assert_eq!(m.children.len(), 1);
        assert_eq!(report.no_magic, 1);
        assert_eq!(report.regex_children_dropped, 1);
    }
}
