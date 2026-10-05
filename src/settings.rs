//! Settings: where the Anthropic API key lives, and the window to manage it.
//!
//! On macOS the key is kept in the login Keychain via the system `security`
//! tool, written through its interactive mode on standard input so the key
//! never appears in a process's arguments. Elsewhere it is kept in
//! `~/.config/theviewer/credentials`, readable only by the user.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Context, RichText};

use crate::app::{MAX_WIDTH, ViewerApp, ZOOM_LEVELS};
use crate::plugin::Category;
use crate::preferences::Preferences;
use crate::raster::{Palette, PixelFormat};
use crate::assistant::{self, Credentials};
use crate::theme;

const KEYCHAIN_SERVICE: &str = "theviewer";
const KEYCHAIN_ACCOUNT: &str = "anthropic-api-key";
const CONSOLE_URL: &str = "https://console.anthropic.com/settings/keys";

/// Where a saved key is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Store {
    /// The macOS login Keychain, under this service name.
    Keychain(String),
    /// A private file.
    File(PathBuf),
}

impl Store {
    /// The Keychain on macOS, a private config file elsewhere.
    pub fn platform_default() -> Store {
        if cfg!(target_os = "macos") {
            Store::Keychain(KEYCHAIN_SERVICE.to_string())
        } else {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
            Store::File(home.join(".config/theviewer/credentials"))
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Store::Keychain(_) => "your macOS Keychain".to_string(),
            Store::File(path) => format!("{} (readable only by you)", path.display()),
        }
    }

    /// The saved key, if there is one.
    pub fn load(&self) -> Option<String> {
        match self {
            Store::Keychain(service) => {
                let output = Command::new("security")
                    .args(["find-generic-password", "-s", service, "-a", KEYCHAIN_ACCOUNT, "-w"])
                    .stderr(Stdio::null())
                    .output()
                    .ok()?;
                let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
                (output.status.success() && !key.is_empty()).then_some(key)
            }
            Store::File(path) => {
                let text = std::fs::read_to_string(path).ok()?;
                let key = text.lines().find_map(|line| line.strip_prefix("anthropic_api_key=")).map(str::trim)?;
                (!key.is_empty()).then(|| key.to_string())
            }
        }
    }

    /// Save `key`, replacing any saved one. The format is checked first.
    pub fn save(&self, key: &str) -> Result<(), String> {
        let key = key.trim();
        check_format(key)?;
        match self {
            Store::Keychain(service) => {
                // `security -i` reads commands from standard input, which keeps
                // the key out of the argument list. check_format guarantees the
                // key holds no quotes or spaces.
                let mut child = Command::new("security")
                    .arg("-i")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("Could not run the Keychain tool: {e}"))?;
                let command = format!("add-generic-password -U -s {service} -a {KEYCHAIN_ACCOUNT} -l \"theviewer Anthropic API key\" -w {key}\n");
                child.stdin.take().ok_or("Keychain tool has no input")?.write_all(command.as_bytes()).map_err(|e| e.to_string())?;
                let output = child.wait_with_output().map_err(|e| e.to_string())?;
                let errors = String::from_utf8_lossy(&output.stderr);
                if !output.status.success() || errors.contains("error") {
                    return Err(format!("The Keychain refused the key: {}", errors.trim()));
                }
                Ok(())
            }
            Store::File(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
                }
                write_private(path, &format!("anthropic_api_key={key}\n"))
            }
        }
    }

    /// Delete the saved key. Removing a key that is not there is not an error.
    pub fn remove(&self) -> Result<(), String> {
        match self {
            Store::Keychain(service) => {
                let status = Command::new("security")
                    .args(["delete-generic-password", "-s", service, "-a", KEYCHAIN_ACCOUNT])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map_err(|e| e.to_string())?;
                // Exit status 44 means "not found", which is fine.
                if status.success() || status.code() == Some(44) { Ok(()) } else { Err("The Keychain could not delete the key".to_string()) }
            }
            Store::File(path) => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.to_string()),
            },
        }
    }
}

/// Write a file that only the owner can read.
fn write_private(path: &std::path::Path, text: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        file.write_all(text.as_bytes()).map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Anthropic API keys look like `sk-ant-…`, with only letters, digits, `-` and `_`.
pub fn check_format(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("Paste a key first".to_string());
    }
    if !key.starts_with("sk-ant-") {
        return Err("That does not look like an Anthropic API key; they start with \"sk-ant-\"".to_string());
    }
    if key.len() < 20 || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("The key has unexpected characters; copy it again from the Anthropic Console".to_string());
    }
    Ok(())
}

/// `sk-ant-…wxyz`: enough to recognise a key without revealing it.
pub fn mask(key: &str) -> String {
    let tail: String = key.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("sk-ant-…{tail}")
}

/// Where the credentials in use came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    Environment,
    Saved,
    AuthToken,
    CliLogin,
}

impl KeySource {
    pub fn describe(&self) -> &'static str {
        match self {
            KeySource::Environment => "the ANTHROPIC_API_KEY environment variable",
            KeySource::Saved => "the key saved in Settings",
            KeySource::AuthToken => "the ANTHROPIC_AUTH_TOKEN environment variable",
            KeySource::CliLogin => "your `ant auth login` session",
        }
    }
}

/// Find credentials in order: environment key, saved key, environment token,
/// then an `ant` CLI login.
pub fn resolve(store: &Store) -> Option<(Credentials, KeySource)> {
    let env = |name: &str| std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    if let Some(key) = env("ANTHROPIC_API_KEY") {
        return Some((Credentials::ApiKey(key), KeySource::Environment));
    }
    if let Some(key) = store.load() {
        return Some((Credentials::ApiKey(key), KeySource::Saved));
    }
    if let Some(token) = env("ANTHROPIC_AUTH_TOKEN") {
        return Some((Credentials::Bearer(token), KeySource::AuthToken));
    }
    if let Ok(Credentials::Bearer(token)) = assistant::cli_login() {
        return Some((Credentials::Bearer(token), KeySource::CliLogin));
    }
    None
}

/// Ask the API whether the credentials work, with a cheap model listing.
pub fn test_credentials(credentials: &Credentials) -> Result<(), String> {
    let config = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(20))).build();
    let agent = ureq::Agent::new_with_config(config);
    let mut request = agent.get("https://api.anthropic.com/v1/models?limit=1").header("anthropic-version", "2023-06-01");
    request = match credentials {
        Credentials::ApiKey(key) => request.header("x-api-key", key),
        Credentials::Bearer(token) => request.header("authorization", format!("Bearer {token}")).header("anthropic-beta", "oauth-2025-04-20"),
    };
    let response = request.call().map_err(|e| format!("Could not reach the Anthropic API: {e}"))?;
    match response.status().as_u16() {
        200 => Ok(()),
        401 => Err("The key was rejected. Check that it is copied in full and has not been revoked.".to_string()),
        403 => Err("The key is valid but not permitted to use the API.".to_string()),
        status => Err(format!("The API answered {status}; try again shortly.")),
    }
}

/// The settings window's state.
pub struct SettingsWindow {
    pub open: bool,
    pub store: Store,
    key_input: String,
    message: Option<(bool, String)>,
    testing: Option<Receiver<Result<(), String>>>,
}

impl Default for SettingsWindow {
    fn default() -> Self {
        SettingsWindow { open: false, store: Store::platform_default(), key_input: String::new(), message: None, testing: None }
    }
}

impl ViewerApp {
    /// Look up credentials again, after a key is added or removed.
    pub fn refresh_credentials(&mut self) {
        self.credentials = resolve(&self.settings.store);
    }

    /// Whether Ask can be used.
    pub fn assistant_available(&self) -> bool {
        self.credentials.is_some()
    }

    pub fn open_settings(&mut self) {
        self.settings.open = true;
        self.settings.message = None;
    }

    pub fn show_settings_window(&mut self, ctx: &Context) {
        if !self.settings.open {
            return;
        }
        if let Some(receiver) = &self.settings.testing
            && let Ok(result) = receiver.try_recv()
        {
            self.settings.message = Some(match result {
                Ok(()) => (true, "The key works.".to_string()),
                Err(message) => (false, message),
            });
            self.settings.testing = None;
        }
        if self.settings.testing.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let mut open = true;
        egui::Window::new("Settings")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().max_height(ctx.content_rect().height() * 0.8).show(ui, |ui| {
                    self.startup_defaults_contents(ui);
                    ui.separator();
                    self.settings_contents(ui);
                });
            });
        self.settings.open = open;
    }

    /// The defaults the viewer starts with. Edits are saved at once and apply
    /// from the next start, unless applied to this window too.
    fn startup_defaults_contents(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("When the viewer starts").heading());
        ui.label(
            RichText::new("Defaults for the next start. The toolbar and View menu change only this window; a file's remembered view and command-line options still win.")
                .color(theme::TEXT_DIM),
        );
        ui.add_space(6.0);
        let mut edited = self.preferences.clone();
        egui::Grid::new("startup-defaults").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
            ui.label("Patterns");
            ui.checkbox(&mut edited.highlight_patterns, "Highlight them in the view and hex dump")
                .on_hover_text("Patterns are detected either way: Findings, the inspector, Decompress and Ask use them.");
            ui.end_row();

            ui.label("Findings");
            ui.checkbox(&mut edited.findings_list_open, "Show the list of findings");
            ui.end_row();

            ui.label("Width");
            ui.horizontal(|ui| {
                ui.add(egui::DragValue::new(&mut edited.width).range(1..=MAX_WIDTH).suffix(" px"));
                ui.checkbox(&mut edited.detect_width_on_open, "Detect it when a file opens");
            });
            ui.end_row();

            ui.label("Pixel format");
            let mut format = edited.pixel_format();
            egui::ComboBox::from_id_salt("default-format").selected_text(format.label()).show_ui(ui, |ui| {
                for option in PixelFormat::ALL {
                    ui.selectable_value(&mut format, option, option.label());
                }
            });
            edited.format = format.short_name().to_string();
            ui.end_row();

            ui.label("Palette");
            let mut palette = edited.palette();
            egui::ComboBox::from_id_salt("default-palette").selected_text(palette.label()).show_ui(ui, |ui| {
                for option in Palette::ALL {
                    ui.selectable_value(&mut palette, option, option.label());
                }
            });
            edited.palette = palette.label().to_string();
            ui.end_row();

            ui.label("Zoom");
            egui::ComboBox::from_id_salt("default-zoom").selected_text(format!("{}×", edited.zoom)).show_ui(ui, |ui| {
                for level in ZOOM_LEVELS {
                    ui.selectable_value(&mut edited.zoom, level, format!("{level}×"));
                }
            });
            ui.end_row();
        });
        egui::CollapsingHeader::new("Kinds of pattern to show").id_salt("default-kinds").show(ui, |ui| {
            ui.label(RichText::new("Hidden kinds are left out of highlights and Findings.").small().color(theme::TEXT_DIM));
            egui::Grid::new("default-kinds-grid").num_columns(3).show(ui, |ui| {
                for (index, category) in Category::ALL.into_iter().enumerate() {
                    let mut shown = edited.shows_kind(category);
                    if ui.checkbox(&mut shown, category.label()).changed() {
                        edited.set_kind_shown(category, shown);
                    }
                    if index % 3 == 2 {
                        ui.end_row();
                    }
                }
            });
        });
        ui.horizontal(|ui| {
            if ui.button("Use this window's settings").on_hover_text("Take the current format, palette, width, zoom and pattern choices as the defaults").clicked() {
                edited = self.current_view_as_preferences();
            }
            if ui.button("Apply to this window").clicked() {
                self.apply_preferences();
            }
            if ui.button("Reset").on_hover_text("Go back to the built-in defaults").clicked() {
                edited = Preferences::default();
            }
        });
        if edited != self.preferences {
            self.set_preferences(edited);
        }
    }

    /// The current window's view and pattern choices, as preferences.
    fn current_view_as_preferences(&self) -> Preferences {
        let mut preferences = Preferences {
            highlight_patterns: self.highlight_patterns,
            findings_list_open: self.pattern_list_open,
            format: self.shape.format.short_name().to_string(),
            palette: self.shape.palette.label().to_string(),
            width: self.shape.width,
            zoom: self.zoom,
            ..self.preferences.clone()
        };
        for category in Category::ALL {
            preferences.set_kind_shown(category, self.pattern_kinds[category.index()]);
        }
        preferences
    }

    fn settings_contents(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Anthropic API key").heading());
        ui.label(
            RichText::new(format!(
                "Needed only for Ask, which sends the question, a snapshot around the cursor and the bytes it chooses to read to Claude ({}). Everything else works without it.",
                assistant::MODEL
            ))
            .color(theme::TEXT_DIM),
        );
        ui.add_space(6.0);
        match self.credentials.clone() {
            Some((credentials, source)) => {
                let shown = match &credentials {
                    Credentials::ApiKey(key) => mask(key),
                    Credentials::Bearer(_) => "OAuth token".to_string(),
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new("●").color(theme::ACCENT));
                    ui.label(format!("Using {shown} from {}.", source.describe()));
                });
                ui.horizontal(|ui| {
                    if ui.add_enabled(self.settings.testing.is_none(), egui::Button::new("Test key")).clicked() {
                        let (sender, receiver) = mpsc::channel();
                        thread::spawn(move || {
                            let _ = sender.send(test_credentials(&credentials));
                        });
                        self.settings.testing = Some(receiver);
                        self.settings.message = None;
                    }
                    if self.settings.testing.is_some() {
                        ui.spinner();
                    }
                    if source == KeySource::Saved && ui.button(RichText::new("Remove key").color(theme::DANGER)).clicked() {
                        self.settings.message = Some(match self.settings.store.remove() {
                            Ok(()) => (true, "Removed.".to_string()),
                            Err(message) => (false, message),
                        });
                        self.refresh_credentials();
                    }
                });
                if source != KeySource::Saved {
                    ui.label(RichText::new("To use a different key here, unset that variable or log out, then save one below.").small().color(theme::TEXT_DIM));
                }
            }
            None => {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("●").color(theme::TEXT_DIM));
                    ui.label("No key yet: Ask is turned off.");
                });
            }
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let field = ui.add(egui::TextEdit::singleline(&mut self.settings.key_input).password(true).hint_text("sk-ant-…").desired_width(320.0));
            let save = ui.button("Save key");
            if save.clicked() || (field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                let result = self.settings.store.save(&self.settings.key_input);
                self.settings.message = Some(match &result {
                    Ok(()) => (true, format!("Saved in {}.", self.settings.store.describe())),
                    Err(message) => (false, message.clone()),
                });
                if result.is_ok() {
                    self.settings.key_input.clear();
                    self.refresh_credentials();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Stored in {}. Create a key at", self.settings.store.describe())).small().color(theme::TEXT_DIM));
            ui.hyperlink_to(RichText::new("console.anthropic.com").small(), CONSOLE_URL);
        });
        if let Some((ok, message)) = &self.settings.message {
            ui.label(RichText::new(message).color(if *ok { theme::ACCENT } else { theme::DANGER }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "sk-ant-api03-abcdefghijklmnop_QRSTUV-wxyz";

    #[test]
    fn keys_are_checked_and_masked() {
        assert!(check_format(KEY).is_ok());
        assert!(check_format("").is_err());
        assert!(check_format("sk-proj-abcdefghijklmnopqrstuvwxyz").unwrap_err().contains("sk-ant-"));
        assert!(check_format("sk-ant-api03-has spaces in it here").is_err());
        assert!(check_format("sk-ant-api03-quote\"injection-xxxxxx").is_err(), "quotes cannot reach the Keychain command");
        assert_eq!(mask(KEY), "sk-ant-…wxyz");
    }

    #[test]
    fn file_store_saves_privately_loads_and_removes() {
        let path = std::env::temp_dir().join(format!("theviewer-credentials-{}", std::process::id()));
        let store = Store::File(path.clone());
        assert_eq!(store.load(), None);
        store.save(&format!("  {KEY}\n")).unwrap();
        assert_eq!(store.load().as_deref(), Some(KEY));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(store.save("not-a-key").is_err());
        assert_eq!(store.load().as_deref(), Some(KEY), "a bad key does not overwrite a good one");
        store.remove().unwrap();
        assert_eq!(store.load(), None);
        store.remove().unwrap();
    }

    #[test]
    fn a_saved_key_is_found_when_the_environment_has_none() {
        if std::env::var("ANTHROPIC_API_KEY").is_ok() {
            return;
        }
        let path = std::env::temp_dir().join(format!("theviewer-credentials-resolve-{}", std::process::id()));
        let store = Store::File(path);
        store.save(KEY).unwrap();
        let (credentials, source) = resolve(&store).expect("found");
        assert_eq!((credentials, source), (Credentials::ApiKey(KEY.to_string()), KeySource::Saved));
        store.remove().unwrap();
    }
}
