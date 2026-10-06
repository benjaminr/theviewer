//! A local corpus of sample captures, for testing the packet code against
//! real traffic and against Wireshark's tshark. Used by the developer tool
//! `cargo run --release --bin capture_corpus -- fetch|run`.
//!
//! [`fetch`] downloads the captures listed on Wireshark's SampleCaptures wiki
//! page into a cache outside the repository (by default
//! `~/.cache/theviewer/corpus/`). They carry no licence statement, so they are
//! never committed and nothing in the repository reads them; tests use
//! captures built by hand. [`run`] then reads every capture with our own
//! readers and dissectors, catching panics and timing each file, decodes the
//! same packets with tshark when it is installed, and compares the two.
//! [`report`] writes what was found as Markdown and CSV, with counts,
//! protocol names and field names only.

pub mod archive;
pub mod compare;
pub mod fetch;
pub mod report;
pub mod run;

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Where the corpus lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusPaths {
    pub root: PathBuf,
    /// Files as downloaded.
    pub downloads: PathBuf,
    /// Captures, unpacked from the downloads.
    pub captures: PathBuf,
    pub manifest: PathBuf,
    pub reports: PathBuf,
}

impl CorpusPaths {
    pub fn new(root: PathBuf) -> CorpusPaths {
        CorpusPaths {
            downloads: root.join("downloads"),
            captures: root.join("captures"),
            manifest: root.join("manifest.json"),
            reports: root.join("report"),
            root,
        }
    }
}

/// The corpus directory: `$THEVIEWER_CORPUS_DIR` when set, else
/// `$HOME/.cache/theviewer/corpus`. A directory inside this source tree is
/// refused, so downloaded captures cannot end up committed.
pub fn default_root() -> Result<PathBuf, String> {
    let root = match std::env::var_os("THEVIEWER_CORPUS_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => {
            let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).ok_or("Neither HOME nor THEVIEWER_CORPUS_DIR is set")?;
            PathBuf::from(home).join(".cache").join("theviewer").join("corpus")
        }
    };
    check_outside_source_tree(&root, Path::new(env!("CARGO_MANIFEST_DIR")))?;
    Ok(root)
}

/// Refuse a corpus directory inside the source tree.
pub fn check_outside_source_tree(root: &Path, source_tree: &Path) -> Result<(), String> {
    let absolute = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let tree = absolute(source_tree);
    // The corpus directory may not exist yet: resolve its nearest existing
    // parent (following links) and add the part still to be created.
    let nearest_existing = root.ancestors().find(|path| path.exists()).unwrap_or(root);
    let not_yet_created = root.strip_prefix(nearest_existing).unwrap_or(Path::new(""));
    let resolved = absolute(nearest_existing).join(not_yet_created);
    if resolved.starts_with(&tree) {
        return Err(format!("{} is inside the source tree; sample captures must stay out of the repository", root.display()));
    }
    Ok(())
}

/// A SHA-256 digest as lower-case hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_corpus_inside_the_source_tree_is_refused() {
        let tree = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(check_outside_source_tree(&tree.join("corpus"), tree).is_err());
        assert!(check_outside_source_tree(&tree.join("src").join("new").join("corpus"), tree).is_err());
        assert!(check_outside_source_tree(&std::env::temp_dir().join("theviewer-corpus-test"), tree).is_ok());
    }

    #[test]
    fn digests_are_lower_case_hex() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
