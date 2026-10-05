//! Bookmarks and per-file settings, kept in a sidecar file next to the
//! document so an analysis session survives a restart.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    pub offset: usize,
    #[serde(default)]
    pub len: usize,
    pub name: String,
    #[serde(default)]
    pub note: String,
}

impl Bookmark {
    pub fn end(&self) -> usize {
        self.offset + self.len.max(1)
    }

    pub fn contains(&self, offset: usize) -> bool {
        offset >= self.offset && offset < self.end()
    }
}

/// The view shape worth remembering for a file.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ShapeMemo {
    pub format: String,
    pub palette: String,
    pub width: usize,
    pub byte_offset: usize,
    pub bit_offset: u32,
    pub row_padding: usize,
    pub zoom: f32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Sidecar {
    #[serde(default)]
    pub bookmarks: Vec<Bookmark>,
    #[serde(default)]
    pub shape: Option<ShapeMemo>,
}

impl Sidecar {
    /// Add or replace the bookmark at `offset`.
    pub fn set(&mut self, bookmark: Bookmark) {
        match self.bookmarks.iter_mut().find(|b| b.offset == bookmark.offset) {
            Some(existing) => *existing = bookmark,
            None => {
                self.bookmarks.push(bookmark);
                self.bookmarks.sort_by_key(|b| b.offset);
            }
        }
    }

    pub fn remove(&mut self, offset: usize) -> bool {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|b| b.offset != offset);
        before != self.bookmarks.len()
    }

    pub fn at(&self, offset: usize) -> Option<&Bookmark> {
        self.bookmarks.iter().find(|b| b.contains(offset))
    }

    /// The next bookmark after `offset`, wrapping to the first.
    pub fn next_after(&self, offset: usize) -> Option<&Bookmark> {
        self.bookmarks.iter().find(|b| b.offset > offset).or_else(|| self.bookmarks.first())
    }

    /// The previous bookmark before `offset`, wrapping to the last.
    pub fn previous_before(&self, offset: usize) -> Option<&Bookmark> {
        self.bookmarks.iter().rev().find(|b| b.offset < offset).or_else(|| self.bookmarks.last())
    }
}

/// `file.bin` keeps its sidecar at `file.bin.theviewer.toml`.
pub fn sidecar_path(document: &Path) -> PathBuf {
    let mut name = document.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".theviewer.toml");
    document.with_file_name(name)
}

pub fn load(path: &Path) -> Result<Sidecar, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Sidecar::default()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

pub fn save(path: &Path, sidecar: &Sidecar) -> Result<(), String> {
    if sidecar.bookmarks.is_empty() && sidecar.shape.is_none() {
        // Nothing worth keeping: remove a stale sidecar rather than write an empty one.
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    let text = toml::to_string_pretty(sidecar).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_round_trips_through_toml() {
        let mut sidecar = Sidecar::default();
        sidecar.set(Bookmark { offset: 0x40, len: 16, name: "header".into(), note: "checked".into() });
        sidecar.set(Bookmark { offset: 0x10, len: 0, name: "start".into(), note: String::new() });
        sidecar.shape = Some(ShapeMemo { format: "rgb8".into(), palette: "Grey".into(), width: 320, byte_offset: 0, bit_offset: 0, row_padding: 0, zoom: 2.0 });
        let dir = std::env::temp_dir();
        let path = dir.join(format!("theviewer-sidecar-{}.toml", std::process::id()));
        save(&path, &sidecar).unwrap();
        let loaded = load(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(loaded, sidecar);
        assert_eq!(loaded.bookmarks[0].offset, 0x10, "sorted by offset");
    }

    #[test]
    fn navigation_wraps_around() {
        let mut sidecar = Sidecar::default();
        sidecar.set(Bookmark { offset: 10, len: 4, name: "a".into(), note: String::new() });
        sidecar.set(Bookmark { offset: 50, len: 0, name: "b".into(), note: String::new() });
        assert_eq!(sidecar.next_after(10).unwrap().name, "b");
        assert_eq!(sidecar.next_after(50).unwrap().name, "a");
        assert_eq!(sidecar.previous_before(10).unwrap().name, "b");
        assert!(sidecar.at(12).is_some());
        assert!(sidecar.at(14).is_none());
        assert!(sidecar.remove(10));
        assert!(!sidecar.remove(10));
    }

    #[test]
    fn missing_sidecar_is_empty_and_empty_sidecar_is_not_written() {
        let path = std::env::temp_dir().join(format!("theviewer-none-{}.toml", std::process::id()));
        assert_eq!(load(&path).unwrap(), Sidecar::default());
        save(&path, &Sidecar::default()).unwrap();
        assert!(!path.exists());
        assert_eq!(sidecar_path(Path::new("/tmp/x/file.bin")), PathBuf::from("/tmp/x/file.bin.theviewer.toml"));
    }
}
