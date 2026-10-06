//! Checks the embedded reference notes' citations against their sources.
//!
//! Usage: `cargo run --bin check_reference [-- --offline]`
//!
//! Every cited RFC is looked up in the RFC Editor's index (title, and whether
//! it is obsoleted), every cited section is looked for in the RFC's text,
//! every port is compared with the IANA's port registry and every link must
//! be https. The index, the registry and RFC text are kept in
//! `~/.cache/theviewer/rfc`; `--offline` uses only what is kept there.
//! Errors make the exit code non-zero; warnings do not.

use std::cell::RefCell;
use std::collections::HashMap;
use std::process::ExitCode;

use theviewer::reference::{self, load_cached_text};
use theviewer::reference_check::{self, Counts, Problem, Severity, Sources};

const RFC_INDEX_URL: &str = "https://www.rfc-editor.org/rfc-index.xml";
const RFC_INDEX_FILE: &str = "rfc-index.xml";
const SERVICES_URL: &str = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv";
const SERVICES_FILE: &str = "service-names-port-numbers.csv";
/// Largest download: the RFC index is about 14 MB.
const DOWNLOAD_LIMIT: usize = 64 * 1024 * 1024;

fn main() -> ExitCode {
    let offline = std::env::args().skip(1).any(|arg| arg == "--offline");
    let library = match reference::embedded_library() {
        Ok(library) => library,
        Err(error) => {
            eprintln!("check_reference: the embedded notes are invalid: {error}");
            return ExitCode::FAILURE;
        }
    };
    let cache = reference::rfc_cache_dir();
    let fetch = |url: &str| -> Result<String, String> {
        if offline {
            return Err("not in the cache, and --offline was given".to_string());
        }
        let bytes = theviewer::sources::fetch_url(url, DOWNLOAD_LIMIT)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    };

    let rfc_index = load_cached_text(cache.as_deref(), RFC_INDEX_FILE, RFC_INDEX_URL, fetch).and_then(|xml| reference_check::parse_rfc_index(&xml));
    let services = load_cached_text(cache.as_deref(), SERVICES_FILE, SERVICES_URL, fetch).map(|csv| reference_check::parse_service_registry(&csv));
    if let Err(error) = &rfc_index {
        println!("note: RFC titles were not checked: {error}");
    }
    if let Err(error) = &services {
        println!("note: ports were not checked: {error}");
    }
    // Each RFC's text is read once, from the cache or the RFC Editor.
    let texts: RefCell<HashMap<u32, Result<String, String>>> = RefCell::new(HashMap::new());
    let rfc_text = |number: u32| texts.borrow_mut().entry(number).or_insert_with(|| reference::load_rfc_text(cache.as_deref(), number, fetch)).clone();
    let sources = Sources { rfc_index: rfc_index.as_ref().ok(), services: services.as_ref().ok(), rfc_text: &rfc_text };

    let mut problems: Vec<Problem> = Vec::new();
    let mut counts = Counts::default();
    for entry in library.entries() {
        let (found, checked) = reference_check::check_entry(entry, &sources);
        problems.extend(found);
        counts += checked;
    }
    for problem in &problems {
        let severity = match problem.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        println!("{severity:<7} {}: {}", problem.entry, problem.message);
    }
    let errors = problems.iter().filter(|problem| problem.severity == Severity::Error).count();
    let warnings = problems.len() - errors;
    println!(
        "Checked {} entries: {} RFC citations, {} sections, {} ports, {} links. {errors} errors, {warnings} warnings.",
        library.entries().len(),
        counts.rfcs,
        counts.sections,
        counts.ports,
        counts.links
    );
    if errors > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
