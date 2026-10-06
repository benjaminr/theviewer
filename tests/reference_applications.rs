//! The application protocol reference notes (reference/network-applications.toml)
//! load, cite their sources and name undissected payloads by port.

use theviewer::reference::{self, Library, Transport};

const APPLICATIONS: &str = include_str!("../reference/network-applications.toml");

fn application_notes() -> Library {
    Library::parse(&[("network-applications.toml", APPLICATIONS)]).expect("network-applications.toml parses")
}

#[test]
fn the_embedded_library_loads_with_the_application_notes() {
    let library = reference::library();
    for entry in application_notes().entries() {
        assert!(library.by_id(&entry.id).is_some(), "{} missing from the embedded library", entry.id);
    }
}

#[test]
fn every_application_note_explains_its_layout_and_cites_a_linked_specification() {
    let notes = application_notes();
    assert!(notes.entries().len() >= 40, "only {} application notes", notes.entries().len());
    for entry in notes.entries() {
        assert!(!entry.organisation.trim().is_empty(), "{} has no organisation", entry.id);
        assert!(!entry.specs.is_empty(), "{} cites no specification", entry.id);
        for spec in &entry.specs {
            assert!(spec.url.starts_with("https://"), "{} cites a non-https link {}", entry.id, spec.url);
        }
    }
}

#[test]
fn every_application_note_is_found_by_its_id_and_names() {
    for entry in application_notes().entries() {
        assert_eq!(reference::lookup(&entry.id).map(|found| found.id.as_str()), Some(entry.id.as_str()));
        for key in &entry.keys {
            assert_eq!(reference::lookup(key).map(|found| found.id.as_str()), Some(entry.id.as_str()), "key {key}");
        }
    }
}

fn names_port(transport: Transport, port: u16, id: &str) -> bool {
    reference::library().by_port(transport, port).iter().any(|entry| entry.id == id)
}

#[test]
fn an_undissected_payload_is_named_by_its_well_known_port() {
    assert!(names_port(Transport::Tcp, 445, "smb2"), "SMB on tcp/445");
    assert!(names_port(Transport::Udp, 5060, "sip"), "SIP on udp/5060");
    assert!(names_port(Transport::Tcp, 5432, "postgresql"), "PostgreSQL on tcp/5432");
    assert!(names_port(Transport::Tcp, 20000, "dnp3"), "DNP3 on tcp/20000");
    assert!(names_port(Transport::Udp, 47808, "bacnet"), "BACnet on udp/47808");
    assert!(names_port(Transport::Tcp, 4840, "opc-ua"), "OPC UA on tcp/4840");
    assert!(names_port(Transport::Tcp, 3389, "rdp"), "RDP on tcp/3389");
    assert!(!names_port(Transport::Udp, 445, "smb2"), "SMB is not named on udp/445");
}

#[test]
fn profinet_frames_are_named_by_their_ethertype() {
    let named = reference::library().by_ethertype(0x8892);
    assert!(named.iter().any(|entry| entry.id == "profinet"));
}
