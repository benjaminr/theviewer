//! Where the viewer keeps its settings, and how they are written.

use std::path::{Path, PathBuf};

/// A file in the app's configuration folder, `~/.config/theviewer`.
pub fn config_file(name: &str) -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/theviewer").join(name))
}

/// Writes `value` as JSON, creating the folder if needed.
pub fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Reads JSON written by [`write_json`]; `None` if it is missing or unreadable.
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}
