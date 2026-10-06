//! The reference notes in `reference/files-catalogue.toml` explain formats
//! the signature catalogue recognises but no parser reads. Each note is keyed
//! by the catalogue ids of its format, so a signature finding leads to it.

use theviewer::catalog::Catalog;
use theviewer::plugin::{Finding, ScanContext};
use theviewer::reference;

fn catalogue_notes() -> Vec<toml::Value> {
    let text = include_str!("../reference/files-catalogue.toml");
    let file: toml::Table = toml::from_str(text).expect("files-catalogue.toml parses");
    file["format"].as_array().expect("files-catalogue.toml has [[format]] entries").clone()
}

fn entry_id(entry: &toml::Value) -> &str {
    entry["id"].as_str().expect("every entry has an id")
}

fn looks_like_catalogue_id(key: &str) -> bool {
    key.contains('/') && !key.contains(' ') && !key.starts_with("stream:")
}

/// Every finding that starts at the first byte of `file`.
fn findings_at_start(file: &[u8]) -> Vec<Finding> {
    let context = ScanContext { base: 0, document_len: file.len(), strides: Vec::new() };
    theviewer::app::build_registry().scan(file, &context).into_iter().filter(|finding| finding.start == 0).collect()
}

/// Catalogue signature findings that start at the first byte of `file`.
fn signatures_at_start(file: &[u8]) -> Vec<Finding> {
    findings_at_start(file).into_iter().filter(|finding| finding.id.starts_with("signature:")).collect()
}

fn assert_signature_leads_to(file: &[u8], expected: &str) {
    let findings = signatures_at_start(file);
    assert!(!findings.is_empty(), "no signature found at the start of the {expected} sample");
    for finding in &findings {
        let notes = reference::lookup(&finding.id).map(|entry| entry.id.as_str());
        assert_eq!(notes, Some(expected), "signature '{}' should lead to the {expected} notes", finding.id);
    }
}

fn sample_pdf() -> Vec<u8> {
    let mut pdf = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    pdf.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    pdf
}

fn sample_sqlite() -> Vec<u8> {
    let mut database = b"SQLite format 3\0".to_vec();
    database.extend_from_slice(&4096u16.to_be_bytes()); // page size
    database.extend_from_slice(&[1, 1, 0, 64, 32, 32]); // versions, reserved, payload fractions
    database.resize(4096, 0);
    database
}

fn sample_ogg() -> Vec<u8> {
    let packet = [0u8; 30];
    let mut page = b"OggS".to_vec();
    page.push(0); // version
    page.push(0x02); // beginning of stream
    page.extend_from_slice(&0u64.to_le_bytes()); // granule position
    page.extend_from_slice(&0x1234u32.to_le_bytes()); // serial number
    page.extend_from_slice(&0u32.to_le_bytes()); // page sequence number
    page.extend_from_slice(&0u32.to_le_bytes()); // CRC, unchecked by the catalogue
    page.push(1); // one segment
    page.push(packet.len() as u8);
    page.extend_from_slice(&packet);
    page
}

fn sample_android_boot_image() -> Vec<u8> {
    let mut image = b"ANDROID!".to_vec();
    image.resize(2048, 0);
    image
}

#[test]
fn the_catalogue_notes_load_with_the_rest_of_the_library() {
    let library = reference::library();
    for entry in catalogue_notes() {
        let id = entry_id(&entry);
        assert!(library.by_id(id).is_some(), "'{id}' is missing from the embedded library");
    }
}

#[test]
fn every_catalogue_note_explains_the_layout_and_cites_a_specification() {
    for entry in catalogue_notes() {
        let id = entry_id(&entry);
        let organisation = entry["organisation"].as_str().unwrap_or_default();
        assert!(!organisation.trim().is_empty(), "{id} does not describe how its bytes are organised");
        let specs = entry.get("specs").and_then(toml::Value::as_array).cloned().unwrap_or_default();
        assert!(!specs.is_empty(), "{id} cites no specification");
        for spec in specs {
            let url = spec["url"].as_str().unwrap_or_default();
            assert!(url.starts_with("https://"), "{id} cites '{url}', which is not an https link");
        }
    }
}

#[test]
fn every_catalogue_name_in_the_notes_is_a_real_signature() {
    let catalog = Catalog::builtin();
    let mut unknown = Vec::new();
    for entry in catalogue_notes() {
        let keys = entry["keys"].as_array().expect("keys is a list");
        for key in keys.iter().filter_map(toml::Value::as_str) {
            if looks_like_catalogue_id(key) && catalog.definition(key).is_none() {
                unknown.push(format!("{} ({key})", entry_id(&entry)));
            }
        }
    }
    assert!(unknown.is_empty(), "keys that no catalogue signature uses: {unknown:?}");
}

#[test]
fn a_pdf_found_at_the_start_of_a_file_leads_to_the_pdf_notes() {
    // A leading '%' also matches a low-priority text signature, so the PDF
    // is announced by the basic file-signature detector rather than the
    // catalogue; its title still leads to the notes.
    let findings = findings_at_start(&sample_pdf());
    let found = findings.iter().any(|finding| reference::lookup_finding(&finding.id, &finding.title).is_some_and(|entry| entry.id == "pdf"));
    let names: Vec<String> = findings.iter().map(|finding| format!("{} ({})", finding.id, finding.title)).collect();
    assert!(found, "no finding at the start of the PDF leads to the PDF notes: {names:?}");
    assert_eq!(reference::lookup("signature:application/pdf").map(|entry| entry.id.as_str()), Some("pdf"));
}

#[test]
fn a_sqlite_database_found_by_its_signature_leads_to_the_sqlite_notes() {
    assert_signature_leads_to(&sample_sqlite(), "sqlite");
}

#[test]
fn an_ogg_page_found_by_its_signature_leads_to_the_ogg_notes() {
    assert_signature_leads_to(&sample_ogg(), "ogg");
}

#[test]
fn an_android_boot_image_found_by_its_signature_leads_to_its_notes() {
    assert_signature_leads_to(&sample_android_boot_image(), "android-boot-image");
}

#[test]
fn firmware_and_disk_signatures_lead_to_their_notes() {
    for (signature, id) in [
        ("signature:firmware/fit-image", "fdt"),
        ("signature:fs/cramfs-be", "cramfs"),
        ("signature:fs/luks", "luks"),
        ("signature:bytecode/pyc-3.12", "pyc"),
        ("signature:win/ole2", "cfb"),
        ("signature:application/x-rar-compressed;version=5", "rar"),
        ("signature:video/x-matroska", "matroska"),
    ] {
        assert_eq!(reference::lookup(signature).map(|entry| entry.id.as_str()), Some(id), "{signature}");
    }
}
