//! What the viewer starts with: the defaults a person chose in Settings.
//!
//! A file's own saved view (its sidecar) and command-line options still take
//! precedence; these only fill in what nothing else decided.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config;
use crate::plugin::Category;
use crate::raster::{Palette, PixelFormat};

/// Zoom the viewer starts at unless told otherwise.
pub const DEFAULT_ZOOM: f32 = 1.0;
/// Width, in pixels per row, the viewer starts at unless told otherwise.
pub const DEFAULT_WIDTH: usize = 512;

/// Startup defaults. Missing fields in an older file take their defaults.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    /// Colour detected patterns in the view and hex dump. They are found
    /// either way, for Findings, the inspector and the tools.
    pub highlight_patterns: bool,
    /// Kinds of pattern left out of highlights and Findings, by label.
    pub hidden_pattern_kinds: Vec<String>,
    /// Whether the Findings pane starts with its list expanded.
    pub findings_list_open: bool,
    /// Write byte values inside pixels when zoomed in far enough.
    pub pixel_values: bool,
    /// Pixel format, by its command-line short name (e.g. "gray8").
    pub format: String,
    /// Palette for single-channel formats, by label (e.g. "Grey").
    pub palette: String,
    pub width: usize,
    pub zoom: f32,
    /// Look for the record width as soon as a file opens, unless the file's
    /// sidecar already remembers one.
    pub detect_width_on_open: bool,
    /// The layout the app opens with: empty for the last session's, else a
    /// recommended layout's command-line name or a saved layout's name.
    pub open_with_layout: String,
    /// Offer the recommended layout that suits each file opened.
    pub suggest_layouts: bool,
    /// Have Wireshark's tshark, when installed, decode the packets the
    /// packet viewer lists. Off unless the user turns it on.
    pub use_tshark: bool,
    /// Where tshark is; empty to look for it on the PATH and in the usual
    /// install locations.
    pub tshark_path: String,
}

impl Default for Preferences {
    fn default() -> Self {
        Preferences {
            highlight_patterns: false,
            hidden_pattern_kinds: Vec::new(),
            findings_list_open: true,
            pixel_values: false,
            format: PixelFormat::Gray8.short_name().to_string(),
            palette: Palette::Grey.label().to_string(),
            width: DEFAULT_WIDTH,
            zoom: DEFAULT_ZOOM,
            detect_width_on_open: false,
            open_with_layout: String::new(),
            suggest_layouts: true,
            use_tshark: false,
            tshark_path: String::new(),
        }
    }
}

impl Preferences {
    pub fn pixel_format(&self) -> PixelFormat {
        PixelFormat::from_short_name(&self.format).unwrap_or(PixelFormat::Gray8)
    }

    pub fn palette(&self) -> Palette {
        Palette::from_name(&self.palette).unwrap_or(Palette::Grey)
    }

    pub fn shows_kind(&self, category: Category) -> bool {
        !self.hidden_pattern_kinds.iter().any(|name| Category::from_name(name) == Some(category))
    }

    pub fn set_kind_shown(&mut self, category: Category, shown: bool) {
        self.hidden_pattern_kinds.retain(|name| Category::from_name(name) != Some(category));
        if !shown {
            self.hidden_pattern_kinds.push(category.label().to_string());
        }
    }
}

/// Where preferences are saved.
pub fn preferences_path() -> Option<PathBuf> {
    config::config_file("preferences.json")
}

/// The saved preferences, or the defaults if there are none.
pub fn load(path: &Path) -> Preferences {
    config::read_json(path).unwrap_or_default()
}

pub fn save(path: &Path, preferences: &Preferences) -> Result<(), String> {
    config::write_json(path, preferences)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_highlights_start_off() {
        assert!(!Preferences::default().highlight_patterns);
        assert!(!Preferences::default().pixel_values, "values inside pixels start off too");
        assert!(!Preferences::default().use_tshark, "tshark is never run unless the user turns it on");
    }

    #[test]
    fn preferences_survive_a_restart() {
        let path = std::env::temp_dir().join(format!("theviewer-preferences-{}.json", std::process::id()));
        let mut preferences = Preferences { highlight_patterns: true, width: 64, ..Preferences::default() };
        preferences.set_kind_shown(Category::Text, false);
        save(&path, &preferences).unwrap();
        let loaded = load(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(loaded, preferences);
        assert!(!loaded.shows_kind(Category::Text));
        assert!(loaded.shows_kind(Category::Timestamp));
    }

    #[test]
    fn an_older_or_damaged_file_falls_back_to_defaults() {
        let path = std::env::temp_dir().join(format!("theviewer-preferences-partial-{}.json", std::process::id()));
        std::fs::write(&path, r#"{ "width": 128, "format": "no-such-format" }"#).unwrap();
        let loaded = load(&path);
        std::fs::write(&path, "not json").unwrap();
        let damaged = load(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(loaded.width, 128);
        assert!(!loaded.highlight_patterns, "missing fields take their defaults");
        assert_eq!(loaded.pixel_format(), PixelFormat::Gray8, "unknown names fall back");
        assert_eq!(damaged, Preferences::default());
    }
}
