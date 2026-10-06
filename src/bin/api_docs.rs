//! Writes the data API reference, `docs/api.md`, from the method table.
//!
//! Usage: `cargo run --bin api_docs`
//!
//! A unit test fails when `docs/api.md` differs from what the table
//! produces, so run this after adding or changing a method.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/api.md");
    match std::fs::write(&path, theviewer::api::reference_markdown()) {
        Ok(()) => {
            println!("wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("could not write {}: {error}", path.display());
            ExitCode::FAILURE
        }
    }
}
