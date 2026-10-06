//! The reference notes in `reference/files.toml` cover what the app finds in
//! files: every parser's findings, every compressed stream, the signature
//! catalogue's names for the same formats, and the fields parsers show.

use theviewer::catalog::Catalog;
use theviewer::compress::{self, Codec};
use theviewer::plugin::{Category, Field, Finding, ScanContext};
use theviewer::reference;

/// Finding ids whose notes live in `reference/network.toml`, checked there.
const NETWORK_FINDINGS: [&str; 2] = ["pcap", "pcapng"];

/// Finding ids that parsers report under a different id from their own, or
/// that come from detectors rather than parsers.
const OTHER_FINDINGS: [&str; 11] = [
    "macho-fat",
    "x509",
    "utf8-text",
    "msgpack",
    "cbor",
    "executable:cortex-m-vectors",
    "media:mpeg-audio",
    "media:aac-adts",
    "media:h264",
    "media:h265",
    "media:pcm",
];

/// Share of a parsed file's field names that should have a note.
const MIN_FIELD_COVERAGE: f64 = 0.7;

fn files_toml_entries() -> Vec<toml::Value> {
    let text = include_str!("../reference/files.toml");
    let file: toml::Table = toml::from_str(text).expect("files.toml parses");
    file["format"].as_array().expect("files.toml has [[format]] entries").clone()
}

fn all_field_names(fields: &[Field], names: &mut Vec<String>) {
    for field in fields {
        names.push(field.name.clone());
        all_field_names(&field.children, names);
    }
}

/// Share of the finding's field names, at every depth, that have a note.
fn field_coverage(finding: &Finding) -> (f64, Vec<String>) {
    let entry = reference::lookup(&finding.id).unwrap_or_else(|| panic!("no notes for '{}'", finding.id));
    let mut names = Vec::new();
    all_field_names(&finding.fields, &mut names);
    let missing: Vec<String> = names.iter().filter(|name| entry.field(name).is_none()).cloned().collect();
    let covered = names.len() - missing.len();
    (covered as f64 / names.len().max(1) as f64, missing)
}

fn parsed(bytes: &[u8], id: &str) -> Finding {
    theviewer::app::build_registry()
        .parse_at(bytes, 0)
        .into_iter()
        .find(|finding| finding.id == id)
        .unwrap_or_else(|| panic!("no '{id}' finding parsed from the sample"))
}

fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(data);
    chunk.extend_from_slice(&[0, 0, 0, 0]); // the parser does not check CRCs
    chunk
}

fn sample_png() -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&4u32.to_be_bytes());
    header.extend_from_slice(&2u32.to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB, no interlace
    let scanlines: Vec<u8> = (0..2).flat_map(|_| std::iter::once(0).chain([200u8; 12])).collect();
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(png_chunk(b"IHDR", &header));
    png.extend(png_chunk(b"IDAT", &compress::compress(Codec::Zlib, &scanlines).unwrap()));
    png.extend(png_chunk(b"IEND", &[]));
    png
}

fn sample_zip() -> Vec<u8> {
    let name = b"notes.txt";
    let content = b"reference notes for every format ".repeat(8);
    let data = compress::compress(Codec::Deflate, &content).unwrap();
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip.extend_from_slice(&0u16.to_le_bytes()); // flags
    zip.extend_from_slice(&8u16.to_le_bytes()); // deflate
    zip.extend_from_slice(&[0; 4]); // time and date
    zip.extend_from_slice(&0u32.to_le_bytes()); // CRC, unchecked by the parser
    zip.extend_from_slice(&(data.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // extra length
    zip.extend_from_slice(name);
    zip.extend_from_slice(&data);
    let central_at = zip.len();
    let mut central = b"PK\x01\x02".to_vec();
    central.extend_from_slice(&[0; 24]);
    central.extend_from_slice(&(name.len() as u16).to_le_bytes());
    central.extend_from_slice(&[0; 16]); // extra and comment lengths, attributes, offset
    central.extend_from_slice(name);
    zip.extend_from_slice(&central);
    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&[0; 4]);
    zip.extend_from_slice(&1u16.to_le_bytes());
    zip.extend_from_slice(&1u16.to_le_bytes());
    zip.extend_from_slice(&(central.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(central_at as u32).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

#[test]
fn every_format_a_built_in_parser_recognises_has_reference_notes() {
    let mut missing = Vec::new();
    for parser in theviewer::parsers::builtin_parsers() {
        let id = parser.id().trim_start_matches("serial.");
        if !NETWORK_FINDINGS.contains(&id) && reference::lookup(id).is_none() {
            missing.push(id.to_string());
        }
    }
    for id in OTHER_FINDINGS {
        if reference::lookup(id).is_none() {
            missing.push(id.to_string());
        }
    }
    assert!(missing.is_empty(), "findings without reference notes: {missing:?}");
}

#[test]
fn every_compressed_stream_has_notes_under_the_names_the_app_gives_it() {
    for codec in Codec::DETECTABLE.into_iter().chain(Codec::HEADERLESS) {
        let label = codec.label();
        for name in [format!("stream:{label}"), format!("{label} stream")] {
            assert!(reference::lookup(&name).is_some(), "no notes for '{name}'");
        }
    }
}

#[test]
fn a_compressed_stream_found_in_a_file_leads_to_its_notes() {
    let mut file = vec![0x55; 300];
    file.extend(compress::compress(Codec::Gzip, &b"a line of log text\n".repeat(200)).unwrap());
    file.extend([0xAA; 300]);
    let context = ScanContext { base: 0, document_len: file.len(), strides: Vec::new() };
    let findings = theviewer::app::build_registry().scan(&file, &context);
    let stream = findings.iter().find(|finding| finding.category == Category::Compressed).expect("the gzip stream is found");
    assert_eq!(reference::lookup(&stream.title).map(|entry| entry.id.as_str()), Some("gzip"), "title '{}'", stream.title);
}

#[test]
fn a_parsed_png_explains_most_of_its_fields() {
    let finding = parsed(&sample_png(), "png");
    let (coverage, missing) = field_coverage(&finding);
    assert!(coverage >= MIN_FIELD_COVERAGE, "{:.0}% of PNG fields have notes; missing {missing:?}", coverage * 100.0);
    let notes = reference::lookup("png").unwrap();
    assert!(notes.field("colour type").is_some_and(|note| note.meaning.contains("palette")));
}

#[test]
fn a_parsed_zip_explains_most_of_its_fields() {
    let finding = parsed(&sample_zip(), "zip");
    let (coverage, missing) = field_coverage(&finding);
    assert!(coverage >= MIN_FIELD_COVERAGE, "{:.0}% of ZIP fields have notes; missing {missing:?}", coverage * 100.0);
}

#[test]
fn a_signature_match_leads_to_the_same_notes_as_the_parser() {
    for (signature, id) in [
        ("signature:image/png", "png"),
        ("signature:application/zip", "zip"),
        ("signature:executable/elf64", "elf"),
        ("signature:partition/mbr", "mbr"),
        ("signature:crypto/der-certificate", "x509"),
        ("signature:application/gzip", "gzip"),
    ] {
        assert_eq!(reference::lookup(signature).map(|entry| entry.id.as_str()), Some(id), "{signature}");
    }
}

#[test]
fn every_catalogue_name_in_the_file_notes_is_a_real_signature() {
    let catalog = Catalog::builtin();
    let mut unknown = Vec::new();
    for entry in files_toml_entries() {
        let keys = entry["keys"].as_array().expect("keys is a list");
        for key in keys.iter().filter_map(|key| key.as_str()) {
            let looks_like_catalogue_id = key.contains('/') && !key.contains(' ') && !key.starts_with("stream:");
            if looks_like_catalogue_id && catalog.definition(key).is_none() {
                unknown.push(key.to_string());
            }
        }
    }
    assert!(unknown.is_empty(), "keys that no catalogue signature uses: {unknown:?}");
}

#[test]
fn the_catalogues_own_names_for_common_formats_open_their_notes() {
    for (finding_id, note) in [
        ("signature:media/png", "png"),
        ("signature:media/bmp", "bmp"),
        ("signature:archive/tar-ustar", "tar"),
        ("signature:archive/zip-central-directory", "zip"),
        ("signature:archive/cpio-newc", "cpio"),
        ("signature:archive/ar", "ar"),
        ("signature:media/mp3-frame", "mpeg-audio"),
    ] {
        let found = theviewer::reference::lookup(finding_id).map(|entry| entry.id.as_str());
        assert_eq!(found, Some(note), "{finding_id}");
    }
}
