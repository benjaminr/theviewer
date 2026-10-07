//! Application state, keyboard shortcuts, file handling and the top-level
//! layout. The raster view lives in `view.rs` and the hex dump in `hex.rs`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, ColorImage, Context, Key, Modifiers, RichText, TextureHandle, TextureOptions, ViewportCommand};

use crate::analysis::{self, PeriodScan};
use crate::catalog::Catalog;
use crate::dialogs::{Answer, FileRequest};
use crate::packing::RowPacker;
use crate::preferences::{self, Preferences};
use crate::parsers;
use crate::plugins::{self, ActionHost, LoadReport, LuaHost};
use crate::bookmarks::{self, Sidecar};
use crate::bus::topics::{FindingsPublished, RecordWidthEstimated, StructureIdentified};
use crate::bus::{Draft, Payload};
use crate::commands::{self, PaletteState};
use crate::compress::{self, Codec, Decompressed};
use crate::assistant::{Assistant, Credentials};
use crate::settings::{KeySource, SettingsWindow};
use crate::dock::{DockState, DockTab};
use crate::layout::{self, Pane};
use crate::layouts::{self, Recommended};
use crate::findings::FindingsFilter;
use crate::folds::Folds;
use crate::legend::{LayerKind, LayerVisibility};
use crate::selection::{self, ColumnSelection, Selection};
use crate::selection_menu::{OperationInputs, SelectionView};
use crate::selection_ops::Operation;
use crate::plot::PlotWindow;
use crate::workbench::{CurveColour, Layout, Workbench};
use crate::media::{self, MediaFormat};
use crate::player::{MediaPlayer, MediaRequest};
use crate::document::Document;
use crate::ops;
use crate::patterns;
use crate::plugin::{Category, Finding, Registry, ScanContext};
use crate::raster::{self, Palette, PixelFormat, RasterStyle, RowDifference, ValueRange};
use crate::search::{self, SearchMode};
use crate::theme;

pub const MAX_WIDTH: usize = 16384;
/// Upper bound on pixels held in the view texture (32M pixels = 128 MiB).
pub const MAX_TEXTURE_PIXELS: usize = 32 * 1024 * 1024;
/// Bytes examined by a period scan.
const SCAN_WINDOW: usize = 192 * 1024;
/// Resolution of the entropy strip.
const ENTROPY_BLOCKS: usize = 1024;
/// Largest region handed to the pattern scanner at once.
const PATTERN_WINDOW_MAX: usize = 4 * 1024 * 1024;
/// Most compressed input a decompression will read.
const DECOMPRESS_INPUT_MAX: usize = 64 * 1024 * 1024;
/// Pattern scan windows are aligned to this so small scrolls reuse a scan.
const PATTERN_ALIGN: usize = 64 * 1024;
pub const ZOOM_LEVELS: [f32; 14] = [
    0.125, 0.25, 0.5, 1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 12.0, 16.0, 24.0, 32.0, 48.0,
];

/// Results sent back from background analysis threads.
pub enum AnalysisMessage {
    Periods(PeriodScan),
    Entropy { document_version: u64, map: Vec<f32> },
    Patterns { key: PatternKey, patterns: Vec<Finding> },
    /// A period scan was cancelled.
    PeriodsCancelled,
    /// A pattern scan was cancelled: the region is left as it was found before.
    PatternsCancelled { key: PatternKey },
}

/// Identifies the region and document state a pattern scan was made for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatternKey {
    pub version: u64,
    pub start: usize,
    pub len: usize,
    pub row_stride: usize,
}

/// A document we descended from by decompressing a block, kept so the user
/// can go back to it with their place intact.
pub struct ParentDocument {
    /// The id the API and the bus know it by, kept while it waits.
    pub id: String,
    pub document: Document,
    /// The version `document.edited` has been published up to, so edits
    /// made to it through the API while it waits are published.
    pub(crate) published_version: u64,
    pub shape: Shape,
    pub cursor: usize,
    pub top_row: usize,
    pub name: String,
    /// Analysis results, kept so Back does not have to rescan.
    patterns: Vec<Finding>,
    pattern_key: Option<PatternKey>,
    period_scan: Option<PeriodScan>,
    entropy_map: Option<Vec<f32>>,
}

/// What a document shown in place of another is to the API and the bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Identity {
    /// A new top-level document: the one shown and its parents are closed.
    New,
    /// Derived from the one shown, which waits on the parent stack.
    Derived,
    /// The parent with this id, come back to; the one shown is closed.
    Back(String),
    /// The same document with new bytes (a live source, or saved and
    /// opened again): its id stays, and what was known about it goes.
    Same,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditMode {
    Overwrite,
    Insert,
}

/// How the flat byte stream is folded into a 2D image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub format: PixelFormat,
    pub palette: Palette,
    /// Pixels per row.
    pub width: usize,
    /// Document offset of the first pixel in row 0.
    pub byte_offset: usize,
    /// Additional bit shift (0..8) applied on top of `byte_offset`.
    pub bit_offset: u32,
    /// Bytes skipped between the end of one row's pixels and the next row.
    pub row_padding: usize,
}

impl Shape {
    pub fn bits_per_pixel(&self) -> usize {
        self.format.bits_per_pixel()
    }

    pub fn row_bytes(&self) -> usize {
        self.format.bytes_for_pixels(self.width)
    }

    pub fn row_stride(&self) -> usize {
        self.row_bytes() + self.row_padding
    }

    pub fn total_rows(&self, document_len: usize) -> usize {
        if document_len <= self.byte_offset {
            return 0;
        }
        (document_len - self.byte_offset).div_ceil(self.row_stride())
    }

    /// Document offset of the byte containing pixel (`row`, `col`).
    pub fn byte_of_pixel(&self, row: usize, col: usize) -> usize {
        let bit = (self.byte_offset + row * self.row_stride()) * 8
            + self.bit_offset as usize
            + col * self.bits_per_pixel();
        bit / 8
    }

    /// Row and first pixel column of a document byte, or `None` if the byte
    /// lies before the view origin.
    pub fn pixel_of_byte(&self, byte: usize) -> Option<(usize, usize)> {
        let origin = self.byte_offset * 8 + self.bit_offset as usize;
        let bit = byte * 8;
        if bit < origin {
            return None;
        }
        let relative = bit - origin;
        let row_bits = self.row_stride() * 8;
        Some((relative / row_bits, (relative % row_bits) / self.bits_per_pixel()))
    }
}

/// Everything that determines the texture contents. If unchanged, the
/// previous texture is reused without touching the document.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RasterKey {
    version: u64,
    shape: Shape,
    top_row: usize,
    rows: usize,
    row_difference: RowDifference,
    /// Fingerprint of the report's regions when the zoomed-out view is
    /// coloured by region (zero when there is no report), `None` otherwise.
    zoomed_out_colours: Option<u64>,
    /// Which ranges were folded out of the layout.
    folds_generation: u64,
}

pub struct ViewerApp {
    pub document: Document,
    /// The id the API and the bus know the shown document by.
    pub(crate) document_id: String,
    /// Documents ever opened in the window, for the next id.
    documents_opened: usize,
    pub shape: Shape,
    pub zoom: f32,
    pub top_row: usize,
    pub pan_x: f32,
    pub visible_rows: usize,
    pub cursor: usize,
    pub anchor: Option<usize>,
    pub edit_mode: EditMode,
    pub pending_low_nibble: bool,
    /// The byte a mouse drag started on; it stays selected whichever way the
    /// drag goes.
    drag_grab: Option<usize>,
    /// The drag in progress makes a column selection (Alt held at its start).
    drag_column: bool,
    /// A column selection: the same bytes in each record. It holds while the
    /// anchor and cursor still span it.
    pub column_selection: Option<ColumnSelection>,
    /// Ranges selected besides the anchor-to-cursor one (Cmd-click adds).
    pub extra_ranges: Vec<(usize, usize)>,
    /// Multi-select mode: plain clicks and drags add sections to the
    /// selection, as Cmd-click and Cmd-drag do. `M` toggles it; Esc leaves it.
    pub multi_select_mode: bool,
    /// Ranges skipped (folded) out of the raster and the hex dump. View
    /// state, not edits: the bytes are still in the document.
    pub folds: Folds,
    pub clipboard: Vec<u8>,
    /// Set by the toolbar; the view resolves it once it knows its own size.
    pub fit_width_requested: bool,
    /// Byte under the pointer in the raster view, for the status bar.
    pub hover: Option<usize>,
    pub show_help: bool,
    last_title: String,

    pub period_scan: Option<PeriodScan>,
    pub scan_pending: bool,
    pub scan_max_period: usize,
    /// Entropy per block over the file on disk, for the strip beside the scrollbar.
    pub entropy_map: Option<Vec<f32>>,
    analysis_tx: Sender<AnalysisMessage>,
    analysis_rx: Receiver<AnalysisMessage>,

    /// Recognised structures in and around the visible region.
    /// Documents above the current one, outermost first.
    pub parents: Vec<ParentDocument>,
    /// Name shown for a derived (decompressed) document, which has no path.
    pub derived_name: Option<String>,
    /// Codec used by "Compress selection".
    pub compress_codec: Codec,
    /// Codec of the last in-place decompression, so one click re-packs it.
    pub inplace_codec: Option<Codec>,

    /// Every detector, parser and codec, built-in or plugin.
    pub registry: Arc<Registry>,
    pub plugin_host: Option<SharedLuaHost>,
    pub palette: PaletteState,
    pub findings_filter: FindingsFilter,
    /// Toolbar text fields that should grab focus on the next frame.
    pub focus_goto: bool,
    pub focus_search: bool,
    pub search_mode: SearchMode,
    pub search_text: String,
    pub search_little_endian: bool,
    pub search_count: Option<usize>,
    /// Bookmarks and remembered shape for the current file.
    pub bookmarks: Sidecar,
    /// Name being typed for a new bookmark, when the prompt is open.
    pub bookmark_prompt: Option<(usize, usize, String)>,
    /// Structure parsed at the cursor, with the cursor and version it was parsed for.
    pub cursor_structure: Option<Finding>,
    cursor_structure_key: Option<(usize, u64)>,
    pub show_structure_fields: bool,
    /// The media window.
    pub media: MediaPlayer,
    /// Requests for the tools (which to show) from menus and links.
    pub dock: DockState,
    /// The arrangement of every pane.
    pub layout: egui_dock::DockState<Pane>,
    /// Named layouts: the recommended ones, the person's own and the last session.
    pub layouts: layouts::Choices,
    /// Where the raster image (or the curve layout's picture) and the hex
    /// dump's rows were drawn last frame; panes move, so tests and tools
    /// read these rather than assume.
    pub raster_rect: Option<egui::Rect>,
    pub hex_body_rect: Option<egui::Rect>,
    /// Whether the layout is saved and restored (the app, not tests).
    pub persist_layout: bool,
    /// The panel layout came from `--layout` for this session only, so it is
    /// not saved over the arrangement the person keeps.
    pub layout_for_session_only: bool,
    /// Startup defaults chosen in Settings.
    pub preferences: Preferences,
    /// An open or save dialog that is showing, and what to do with its answer.
    pub file_request: Option<(FileRequest, FileAction)>,
    /// The toolbar arrangement the person dragged into place, as rows of
    /// group keys; `None` packs the groups automatically.
    pub toolbar_rows: Option<Vec<Vec<String>>>,
    /// The "ask the file" conversation.
    pub assistant: Assistant,
    /// Credentials for Ask, and where they came from; `None` turns Ask off.
    pub credentials: Option<(Credentials, KeySource)>,
    pub settings: SettingsWindow,
    /// The plot window.
    pub plot: PlotWindow,
    /// State of the dock's tools: report, unpacking, live sources and more.
    pub bench: Workbench,
    /// Media found at the cursor: (cursor, version) it was computed for, and the result.
    media_hint: Option<MediaHint>,
    /// Thumbnail of the image under the cursor, keyed by start and version.
    pub image_preview: Option<(usize, u64, TextureHandle)>,
    pub patterns: Vec<Finding>,
    pattern_key: Option<PatternKey>,
    pattern_pending: Option<PatternKey>,
    /// Colour detected patterns in the view and hex dump (they are found
    /// either way).
    pub highlight_patterns: bool,
    /// Which kinds of pattern are shown, in highlights and in Findings.
    pub pattern_kinds: [bool; Category::ALL.len()],
    pub pattern_list_open: bool,
    /// Which highlight layers are drawn (patterns keep their own flags above).
    pub layers: LayerVisibility,
    /// The layer the legend is pointing at, picked out in both views this frame.
    emphasis: Option<LayerKind>,
    /// The layer the legend pointed at during this frame, for the next one.
    emphasis_next: Option<LayerKind>,
    /// Bytes pointed at (a panel's field row under the pointer), as
    /// `(start, len)`, outlined in both views: what `view.pointed` last said.
    pub(crate) pointed: Option<(usize, usize)>,
    /// The bytes panels point at during this frame, published on
    /// `view.pointed` at its end when they changed.
    pointed_next: Option<(usize, usize)>,
    /// Overlay rectangles the raster drew last frame, per layer; read by
    /// tests and handy when checking what a toggle does.
    pub overlays_drawn: std::collections::BTreeMap<LayerKind, usize>,
    /// Matches of the Find box in and around the visible bytes.
    search_highlight: Option<SearchHighlight>,
    /// The match of the Find box last selected and which match it is, so
    /// the next Find next or previous counts on from it.
    pub(crate) counted_match: Option<crate::journal::provenance::capture::CountedMatch>,

    texture: Option<TextureHandle>,
    raster_key: Option<RasterKey>,
    byte_buffer: Vec<u8>,
    /// Bytes at the start of `byte_buffer` that precede the top row: the row
    /// above, kept as the reference for the row difference.
    raster_prefix: usize,
    /// How each row is compared with the one above before it is drawn.
    pub row_difference: RowDifference,
    /// Range the numeric heatmap formats spread over the palette, worked out
    /// from the visible window; `None` for other formats.
    pub value_range: Option<ValueRange>,
    /// When zoomed out so far that a screen pixel covers several bytes, colour
    /// the raster by region (or block class and entropy) rather than showing
    /// raw subsampled bytes.
    pub colour_regions_when_zoomed_out: bool,
    /// Write each byte's value inside its pixel when zoomed in far enough.
    /// Off unless asked for, so the picture stays a picture.
    pub show_pixel_values: bool,
    /// Hex values the raster drew inside pixels last frame (zero when zoomed
    /// out or over the per-frame limit); read by tests and the status bar.
    pub hex_labels_drawn: usize,
    /// Template and structure field outlines the raster drew last frame.
    pub field_outlines_drawn: usize,
    /// Markers for skipped ranges the raster drew last frame.
    pub fold_markers_drawn: usize,
    pub last_raster_ms: f32,
    pub last_raster_pixels: usize,

    pub status: String,
    /// Actions asked for while a panel's state was lent out to draw it,
    /// carried out at the start of the next frame (see `perform_later`).
    pub(crate) actions_after_drawing: Vec<(String, serde_json::Value, crate::journal::DerivedFrom)>,
    pub hex_top_row: usize,
    /// Rows the hex dump showed last frame, so the raster can outline them
    /// and cursor reveals know how much fits.
    pub hex_visible_rows: usize,
    goto_text: String,
    pub(crate) insert_count: usize,
    pub(crate) insert_value_text: String,
    pub(crate) fill_value_text: String,
    pub(crate) shift_amount: i64,
    move_amount: i64,
    /// Values typed into the Selection menu's fields.
    pub inputs: OperationInputs,
    /// The view the person last pointed into, which shows the floating toolbar.
    pub selection_view: SelectionView,
    /// A drag moving the selected bytes, while one is in progress.
    pub(crate) move_drag: Option<crate::selection_drag::MoveDrag>,
    /// The Insert window (opened with I) is showing.
    pub insert_dialog_open: bool,
    scroll_accumulator: f32,
    /// What tools, panels and plugins have published: facts and events.
    pub bus: crate::bus::Bus,
    /// The packet sets made through the API.
    pub packet_sets: crate::api::packet_sets::PacketSets,
    /// The file's regions as the report published them on `regions.mapped`,
    /// kept by a reaction for the views that colour or label by region.
    pub mapped_regions: Arc<Vec<crate::explain::Region>>,
    /// What the app last published of its own state.
    pub(crate) bus_watch: crate::bus::window::BusWatch,
    /// Run for each message the bus delivers.
    pub(crate) reactions: Vec<crate::bus::window::Reaction>,
    /// Methods plugins registered, which join the data API's table.
    pub plugin_methods: Vec<Arc<crate::api::RegisteredMethod>>,
    /// Handlers plugins subscribed to topics with.
    pub plugin_subscriptions: Vec<Arc<crate::plugins::Subscription>>,
    /// Messages waiting for plugins' handlers.
    pub plugin_inbox: crate::bus::window::PluginInbox,
    /// Calls from plugins, Ask and other clients waiting for the person to
    /// allow or deny them, oldest first; the first is shown.
    pub confirmations: crate::confirmations::Confirmations,
    /// "Run recipe…": pick a saved recipe, preview it on this file, run it.
    pub recipe_window: crate::recipes::window::RecipeWindow,
    /// The session's journal: every call made through the API that changed
    /// something, for the History tab, undo across steps and recipes.
    pub journal: crate::journal::Journal,
}

/// Matches of the Find box within a window of the document, for highlighting.
struct SearchHighlight {
    version: u64,
    needle: Vec<u8>,
    start: usize,
    len: usize,
    matches: Vec<usize>,
}

/// Cached media lookup: the (cursor, document version) it was computed for,
/// and the media start and format found there, if any.
type MediaHint = ((usize, u64), Option<(usize, MediaFormat)>);

/// A scripted action a plugin offers, as shown in the command palette.
#[derive(Clone, Debug)]
pub struct PluginAction {
    pub id: String,
    pub title: String,
}

/// The Lua host, shared between the UI thread (actions, reload) and the
/// registry's background scans (detectors hold their own script handles).
pub type SharedLuaHost = Arc<std::sync::Mutex<LuaHost>>;

/// Where user signature files live, alongside the plugin directory.
pub fn user_catalog_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/theviewer/catalog"))
}

/// Load the Lua plugins from the default directories.
pub fn load_plugin_host() -> (SharedLuaHost, Vec<LoadReport>) {
    let mut host = LuaHost::new();
    let mut reports = Vec::new();
    for dir in plugins::default_dirs() {
        reports.extend(host.load_dir(&dir));
    }
    (Arc::new(std::sync::Mutex::new(host)), reports)
}

/// Assemble every detector, parser and codec the app knows about: the
/// built-in scanners and codecs, the signature catalogue (with any user
/// signature files), the structure parsers, and whatever Lua plugins
/// registered.
pub fn build_registry() -> Registry {
    build_registry_with(None)
}

pub fn build_registry_with(host: Option<&SharedLuaHost>) -> Registry {
    let mut registry = Registry::new();
    for detector in patterns::builtin_detectors() {
        registry.add_detector_arc(detector);
    }
    for codec in compress::builtin_codecs() {
        registry.add_codec_arc(codec);
    }
    let mut catalog = Catalog::builtin();
    // Having no user catalogue is the normal case; only report real errors.
    if let Some(dir) = user_catalog_dir().filter(|dir| dir.is_dir())
        && let Err(message) = catalog.load_dir(&dir)
    {
        eprintln!("theviewer: user catalogue ignored: {message}");
    }
    registry.add_detector(catalog);
    registry.add_detector(crate::cortex_m::CortexMVectorDetector);
    registry.add_detector(crate::crypto_constants::CryptoConstantDetector);
    registry.add_detector(crate::elementary::ElementaryStreamDetector);
    for parser in parsers::builtin_parsers() {
        registry.add_parser_arc(parser);
    }
    for detector in parsers::builtin_detectors() {
        registry.add_detector_arc(detector);
    }
    if let Some(host) = host
        && let Ok(host) = host.lock()
    {
        for detector in host.detectors() {
            registry.add_detector_arc(detector);
        }
        for parser in host.parsers() {
            registry.add_parser_arc(parser);
        }
        for codec in host.codecs() {
            registry.add_codec_arc(codec);
        }
    }
    registry
}

/// What to do with the path a file dialog returns.
pub enum FileAction {
    /// Write the selection or stream at the cursor, or its decompressed contents.
    Extract { decompressed: bool },
    /// Compare the document with the chosen file.
    Compare,
    /// Call `method` with `params`, the chosen path set as `params[path_field]`
    /// (see [`ViewerApp::save_dialog_then_call`]).
    Call { method: String, params: serde_json::Value, path_field: String },
}

/// Whether a dialog picks an existing file or a place to save one.
pub enum DialogKind {
    Open,
    Save,
}

/// Initial settings supplied on the command line.
#[derive(Debug, Default, Clone)]
pub struct Launch {
    pub path: Option<PathBuf>,
    pub format: Option<PixelFormat>,
    pub palette: Option<Palette>,
    pub width: Option<usize>,
    pub offset: Option<usize>,
    pub zoom: Option<f32>,
    /// Initial cursor position.
    pub cursor: Option<usize>,
    /// Run a period scan immediately after loading.
    pub detect: bool,
    /// Open the media at the cursor once loaded.
    pub open_media: bool,
    /// Open the tools dock on this tab (by its label, e.g. "report").
    pub tool: Option<String>,
    /// Restore and save the panel layout (the app sets this; tests do not).
    pub restore_layout: bool,
    /// Start with a layout for this session: a recommended one (overview,
    /// network, structure, firmware, signals, forensics, compare or focus;
    /// default is overview) or one the person saved, by name.
    pub layout: Option<String>,
}

impl ViewerApp {
    pub fn new(launch: Launch) -> Self {
        let (analysis_tx, analysis_rx) = mpsc::channel();
        let mut app = ViewerApp {
            document: Document::default(),
            document_id: format!("doc-{}", 1),
            documents_opened: 1,
            shape: Shape {
                format: PixelFormat::Gray8,
                palette: Palette::Grey,
                width: 512,
                byte_offset: 0,
                bit_offset: 0,
                row_padding: 0,
            },
            zoom: 1.0,
            top_row: 0,
            pan_x: 0.0,
            visible_rows: 1,
            cursor: 0,
            anchor: None,
            edit_mode: EditMode::Overwrite,
            pending_low_nibble: false,
            drag_grab: None,
            drag_column: false,
            column_selection: None,
            extra_ranges: Vec::new(),
            multi_select_mode: false,
            folds: Folds::default(),
            clipboard: Vec::new(),
            fit_width_requested: false,
            hover: None,
            show_help: false,
            last_title: String::new(),
            period_scan: None,
            scan_pending: false,
            scan_max_period: 4096,
            entropy_map: None,
            analysis_tx,
            analysis_rx,
            parents: Vec::new(),
            derived_name: None,
            compress_codec: Codec::Zlib,
            inplace_codec: None,
            patterns: Vec::new(),
            pattern_key: None,
            pattern_pending: None,
            highlight_patterns: true,
            registry: Arc::new(Registry::new()),
            plugin_host: None,
            palette: PaletteState::default(),
            findings_filter: FindingsFilter::default(),
            focus_goto: false,
            focus_search: false,
            search_mode: SearchMode::Hex,
            search_text: String::new(),
            search_little_endian: true,
            search_count: None,
            bookmarks: Sidecar::default(),
            bookmark_prompt: None,
            cursor_structure: None,
            cursor_structure_key: None,
            show_structure_fields: true,
            image_preview: None,
            media: MediaPlayer::default(),
            dock: DockState::default(),
            layout: Recommended::Overview.build(),
            layouts: layouts::Choices::default(),
            raster_rect: None,
            hex_body_rect: None,
            persist_layout: false,
            layout_for_session_only: false,
            toolbar_rows: None,
            preferences: Preferences::default(),
            file_request: None,
            assistant: Assistant::default(),
            credentials: None,
            settings: SettingsWindow::default(),
            plot: PlotWindow::default(),
            bench: Workbench::default(),
            media_hint: None,
            pattern_kinds: [true; Category::ALL.len()],
            // Findings has its own pane now, so its list starts open.
            pattern_list_open: true,
            layers: LayerVisibility::default(),
            emphasis: None,
            emphasis_next: None,
            pointed: None,
            pointed_next: None,
            overlays_drawn: std::collections::BTreeMap::new(),
            search_highlight: None,
            counted_match: None,
            texture: None,
            raster_key: None,
            byte_buffer: Vec::new(),
            raster_prefix: 0,
            row_difference: RowDifference::None,
            value_range: None,
            colour_regions_when_zoomed_out: true,
            show_pixel_values: false,
            hex_labels_drawn: 0,
            field_outlines_drawn: 0,
            fold_markers_drawn: 0,
            last_raster_ms: 0.0,
            last_raster_pixels: 0,
            status: "Open a file (Cmd+O) or drop one onto the window".to_string(),
            actions_after_drawing: Vec::new(),
            hex_top_row: 0,
            hex_visible_rows: 1,
            goto_text: String::new(),
            insert_count: 1,
            insert_value_text: "00".to_string(),
            fill_value_text: "00".to_string(),
            shift_amount: 1,
            move_amount: 1,
            inputs: OperationInputs::default(),
            selection_view: SelectionView::default(),
            move_drag: None,
            insert_dialog_open: false,
            scroll_accumulator: 0.0,
            bus: crate::bus::Bus::new(),
            packet_sets: Default::default(),
            mapped_regions: Arc::default(),
            bus_watch: Default::default(),
            reactions: crate::bus::window::builtin_reactions(),
            plugin_methods: Vec::new(),
            plugin_subscriptions: Vec::new(),
            plugin_inbox: Default::default(),
            confirmations: Default::default(),
            recipe_window: Default::default(),
            journal: crate::journal::Journal::new(),
        };
        if launch.restore_layout {
            app.persist_layout = true;
            app.toolbar_rows = layout::toolbar_path().and_then(|path| layout::load_toolbar(&path));
            if let Some(path) = preferences::preferences_path() {
                app.preferences = preferences::load(&path);
            }
            let last_session = layout::layout_path().and_then(|path| layout::load(&path));
            app.open_startup_layout(last_session);
        }
        app.apply_preferences();
        if let Some(name) = &launch.layout {
            if !app.open_layout_named(name) {
                app.status = format!("No layout called '{name}'; showing the {}", Recommended::Overview.label());
                app.apply_recommended(Recommended::Overview);
            }
            app.layout_for_session_only = true;
        }
        app.refresh_credentials();
        let (host, reports) = load_plugin_host();
        app.registry = Arc::new(build_registry_with(Some(&host)));
        app.plugin_host = Some(host);
        app.refresh_plugin_hooks();
        let failed = failed_reports(&reports);
        if !failed.is_empty() {
            app.status = format!("Some plugins failed to load: {failed}");
        }
        let unread_notes = &crate::reference::loaded_notes().problems;
        if !unread_notes.is_empty() {
            for problem in unread_notes {
                eprintln!("theviewer: reference notes ignored: {problem}");
            }
            app.status = format!("{} file(s) of your reference notes could not be read; see Reference › Browse all", unread_notes.len());
        }
        if let Some(path) = &launch.path {
            app.load_path(path);
            // A layout that opens on the packets lists them from the start.
            if app.layouts.current.as_deref() == Some(Recommended::Network.label()) {
                crate::panel_packets::load_capture_if_empty(&mut app);
            }
        }
        if let Some(format) = launch.format {
            app.shape.format = format;
        }
        if let Some(palette) = launch.palette {
            app.shape.palette = palette;
        }
        if let Some(width) = launch.width {
            app.set_width(width);
        }
        if let Some(offset) = launch.offset {
            app.shape.byte_offset = offset.min(app.document.len());
        }
        if let Some(zoom) = launch.zoom {
            app.apply_zoom_delta(zoom / app.zoom);
        }
        if let Some(cursor) = launch.cursor {
            app.set_cursor(cursor, false);
            app.reveal_cursor_centred();
            app.reveal_cursor_in_hex(true);
        }
        if launch.detect && !app.document.is_empty() {
            app.scan_periods_by_itself();
        }
        if launch.open_media {
            app.open_media();
        }
        if let Some(name) = &launch.tool {
            app.open_launch_tool(name);
        }
        app
    }

    /// Open the tool `--tool` named, starting the work it shows; a name
    /// that is no tool is reported in the status line.
    fn open_launch_tool(&mut self, name: &str) {
        // "dot-plot" names the "Dot plot" tab.
        let wanted = name.replace(' ', "-");
        let Some(tab) = DockTab::ALL.into_iter().find(|tab| tab.label().replace(' ', "-").eq_ignore_ascii_case(&wanted)) else {
            self.status = format!("No tool called '{name}'; theviewer --help lists them");
            return;
        };
        self.dock.open = true;
        self.dock.tab = tab;
        match tab {
            DockTab::Report => self.start_report(),
            DockTab::Unpacked => self.start_unpack(),
            DockTab::Statistics => crate::analysis_stats::start_statistics(self),
            DockTab::Protocol => crate::analysis_tools::start_protocol(self),
            DockTab::Packets => crate::panel_packets::auto_load(self),
            DockTab::Trigrams => {
                let mut trigrams = std::mem::take(&mut self.bench.panels.trigrams);
                crate::panel_trigram::start_counting(&mut trigrams, self);
                self.bench.panels.trigrams = trigrams;
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Files
    // ------------------------------------------------------------------

    /// Start from the chosen defaults: highlights, kinds, the findings list,
    /// pixel format, palette, width and zoom.
    pub fn apply_preferences(&mut self) {
        let preferences = self.preferences.clone();
        self.highlight_patterns = preferences.highlight_patterns;
        for category in Category::ALL {
            self.pattern_kinds[category.index()] = preferences.shows_kind(category);
        }
        self.pattern_list_open = preferences.findings_list_open;
        self.show_pixel_values = preferences.pixel_values;
        self.shape.format = preferences.pixel_format();
        self.shape.palette = preferences.palette();
        self.set_width(preferences.width);
        self.apply_zoom_delta(preferences.zoom / self.zoom);
    }

    /// Keep new defaults for next time. They take effect on the next start;
    /// the current view is left as it is.
    pub fn set_preferences(&mut self, preferences: Preferences) {
        self.preferences = preferences;
        if self.persist_layout
            && let Some(path) = preferences::preferences_path()
            && let Err(message) = preferences::save(&path, &self.preferences)
        {
            self.status = format!("Could not save preferences: {message}");
        }
    }

    pub fn load_path(&mut self, path: &Path) {
        self.load_path_as(path, Identity::New);
    }

    /// Open the file at `path` in place of the document shown, as `identity`
    /// says: a new document, or the same one saved and opened again.
    fn load_path_as(&mut self, path: &Path, identity: Identity) {
        match Document::open(path) {
            Ok(document) => {
                self.stop_live_sources();
                let closed = self.closed_by(&identity);
                self.document = document;
                self.bench.document_changed();
                self.mapped_regions = Arc::default();
                self.derived_name = None;
                self.cursor = 0;
                self.anchor = None;
                self.clear_secondary_selection();
                self.folds.clear();
                self.top_row = 0;
                self.pan_x = 0.0;
                self.shape.byte_offset = 0;
                self.shape.bit_offset = 0;
                self.raster_key = None;
                self.period_scan = None;
                self.patterns.clear();
                self.pattern_key = None;
                self.cursor_structure = None;
                self.cursor_structure_key = None;
                self.start_entropy_map();
                self.take_identity(identity);
                self.publish_document_replaced(closed);
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                self.status = format!("Loaded {name}");
                let remembered_shape = self.load_sidecar(path);
                self.suggest_layout_for_file();
                if self.preferences.detect_width_on_open && !remembered_shape && !self.document.is_empty() {
                    self.scan_periods_by_itself();
                }
            }
            Err(error) => self.status = format!("Failed to open {}: {error:#}", path.display()),
        }
    }

    /// Restore bookmarks and the remembered view. Returns whether the sidecar
    /// remembered a view shape.
    fn load_sidecar(&mut self, path: &Path) -> bool {
        match bookmarks::load(&bookmarks::sidecar_path(path)) {
            Ok(sidecar) => {
                let remembered_shape = sidecar.shape.is_some();
                if let Some(memo) = &sidecar.shape {
                    if let Some(format) = PixelFormat::from_short_name(&memo.format) {
                        self.shape.format = format;
                    }
                    if let Some(palette) = Palette::from_name(&memo.palette) {
                        self.shape.palette = palette;
                    }
                    self.shape.width = memo.width.clamp(1, MAX_WIDTH);
                    self.shape.byte_offset = memo.byte_offset.min(self.document.len());
                    self.shape.bit_offset = memo.bit_offset.min(7);
                    self.shape.row_padding = memo.row_padding;
                    if memo.zoom > 0.0 {
                        self.apply_zoom_delta(memo.zoom / self.zoom);
                    }
                }
                if !sidecar.bookmarks.is_empty() {
                    self.status = format!("{} ({} bookmarks)", self.status, sidecar.bookmarks.len());
                }
                self.bookmarks = sidecar;
                remembered_shape
            }
            Err(message) => {
                self.status = format!("Sidecar ignored: {message}");
                false
            }
        }
    }

    /// Persist bookmarks and the current shape next to the file.
    pub fn save_sidecar(&mut self) {
        let Some(path) = self.document.path().map(Path::to_path_buf) else { return };
        if !self.parents.is_empty() {
            return;
        }
        self.bookmarks.shape = Some(bookmarks::ShapeMemo {
            format: self.shape.format.short_name().to_string(),
            palette: self.shape.palette.label().to_string(),
            width: self.shape.width,
            byte_offset: self.shape.byte_offset,
            bit_offset: self.shape.bit_offset,
            row_padding: self.shape.row_padding,
            zoom: self.zoom,
        });
        if let Err(message) = bookmarks::save(&bookmarks::sidecar_path(&path), &self.bookmarks) {
            self.status = format!("Could not save bookmarks: {message}");
        }
    }

    /// Ask for a file and open it in place of what is shown, as
    /// `documents.open`.
    pub fn open_dialog(&mut self) {
        self.open_dialog_then_call("Open file", "documents.open", serde_json::json!({ "discard_unsaved": true }), "path");
    }

    /// Show a file dialog without blocking the window; `action` runs when a
    /// path is chosen. Only one dialog is shown at a time.
    pub fn ask_for_file(&mut self, kind: DialogKind, dialog: rfd::AsyncFileDialog, action: FileAction) {
        if self.file_request.is_some() {
            self.status = "A file dialog is already open".to_string();
            return;
        }
        let request = match kind {
            DialogKind::Open => FileRequest::open(dialog),
            DialogKind::Save => FileRequest::save(dialog),
        };
        self.file_request = Some((request, action));
    }

    /// Act on a file dialog's answer once it arrives.
    fn poll_file_request(&mut self, ctx: &Context) {
        let Some((request, _)) = &self.file_request else { return };
        let Some(answer) = request.poll(ctx) else { return };
        let Some((_, action)) = self.file_request.take() else { return };
        if let Answer::Chosen(path) = answer {
            self.complete_file_action(action, &path);
        }
    }

    fn complete_file_action(&mut self, action: FileAction, path: &Path) {
        match action {
            FileAction::Extract { decompressed: true } => self.export_decompressed_to(path),
            FileAction::Extract { decompressed: false } => self.export_bytes_to(path),
            FileAction::Compare => {
                // The comparison's result is collected by the Diff tab, so show it.
                self.dock.open = true;
                self.dock.tab = DockTab::Diff;
                self.bench.analysis.diff_other = Some(path.display().to_string());
                crate::analysis_tabs::start_diff(self, path.to_path_buf());
            }
            FileAction::Call { method, params, path_field } => {
                // A call that wrote a file (documents.export, say) says how much.
                if let Ok(result) = self.call_with_chosen_path(&method, params, &path_field, path)
                    && let Some(written) = result.get("written").and_then(serde_json::Value::as_u64)
                {
                    self.status = format!("Saved {} to {}", compress::human_bytes(written as usize), path.display());
                }
            }
        }
    }

    /// Save over the file, as `documents.save`; a document with no file yet
    /// asks where.
    pub fn save(&mut self) {
        match self.document.path() {
            Some(_) => drop(self.perform("documents.save", serde_json::json!({}))),
            None => self.save_as_dialog(),
        }
    }

    /// Ask where to save, then save there as `documents.save`.
    pub fn save_as_dialog(&mut self) {
        let name = self.document.path().and_then(Path::file_name).map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        self.save_dialog_then_call("Save as", &name, "documents.save", serde_json::json!({}), "path");
    }

    /// Save the document to `path` and say so in the status bar; the error
    /// says why not.
    pub(crate) fn save_to(&mut self, path: &Path) -> Result<(), String> {
        match self.document.save_to(path) {
            Ok(()) => {
                let cursor = self.cursor;
                let top_row = self.top_row;
                let shape = self.shape;
                // Reopen so the piece table collapses back to a single mapping.
                self.load_path_as(path, Identity::Same);
                self.shape = shape;
                self.cursor = cursor.min(self.document.len());
                self.top_row = top_row;
                self.status = format!("Saved {}", path.display());
                Ok(())
            }
            Err(error) => {
                self.status = format!("Save failed: {error:#}");
                Err(format!("could not save {}: {error:#}", path.display()))
            }
        }
    }

    pub fn new_document(&mut self) {
        self.stop_live_sources();
        self.bookmarks = Sidecar::default();
        self.install_document(Document::default(), None, Identity::New);
        self.entropy_map = None;
        self.status = "New empty document".to_string();
    }

    // ------------------------------------------------------------------
    // Cursor and selection
    // ------------------------------------------------------------------

    /// Current selection as `(start, len)`, if any bytes are selected.
    pub fn selection(&self) -> Option<(usize, usize)> {
        let anchor = self.anchor?;
        let start = anchor.min(self.cursor);
        let end = anchor.max(self.cursor).min(self.document.len());
        (end > start).then_some((start, end - start))
    }

    /// What is selected, of whichever kind: a range, a column of every
    /// record, or several ranges. `selection()` stays the primary range.
    pub fn current_selection(&self) -> Option<Selection> {
        let primary = self.selection();
        let len = self.document.len();
        if let Some(column) = self.column_selection
            && primary == clip_range(column.span(), len)
        {
            return Some(Selection::Columns(column));
        }
        if !self.extra_ranges.is_empty() {
            let mut ranges: Vec<(usize, usize)> = self.extra_ranges.iter().filter_map(|&range| clip_range(range, len)).collect();
            ranges.extend(primary);
            let ranges = selection::normalise_ranges(ranges);
            return match ranges.as_slice() {
                [] => None,
                [(start, len)] => Some(Selection::Range(*start, *len)),
                _ => Some(Selection::Ranges(ranges)),
            };
        }
        primary.map(|(start, len)| Selection::Range(start, len))
    }

    /// Every selected range, in document order.
    pub fn selection_ranges(&self) -> Vec<(usize, usize)> {
        self.current_selection().map_or_else(Vec::new, |selected| selected.ranges(self.document.len()))
    }

    /// The selected ranges that overlap `[start, end)`; cheap for a column
    /// over many records.
    pub fn selection_ranges_in(&self, start: usize, end: usize) -> Vec<(usize, usize)> {
        self.current_selection().map_or_else(Vec::new, |selected| selected.ranges_within(start, end, self.document.len()))
    }

    /// Whether `offset` is selected, in any kind of selection.
    pub fn is_selected(&self, offset: usize) -> bool {
        self.current_selection().is_some_and(|selected| selected.contains(offset))
    }

    /// A short description of the selection for the legend, inspector and
    /// status bar, such as "312 B", "column 4–7 × 120 rows (480 B)" or
    /// "5 ranges, 312 B"; `None` when nothing is selected.
    pub fn selection_summary(&self) -> Option<String> {
        self.current_selection().map(|selected| selected.describe(self.document.len()))
    }

    /// Forget the column and the extra ranges, leaving the plain selection.
    pub fn clear_secondary_selection(&mut self) {
        self.column_selection = None;
        self.extra_ranges.clear();
    }

    /// Select several ranges at once, `primary` (or the last) being the
    /// anchor-to-cursor one.
    pub fn select_ranges(&mut self, ranges: Vec<(usize, usize)>, primary: Option<(usize, usize)>) {
        let len = self.document.len();
        let mut ranges = selection::normalise_ranges(ranges.into_iter().filter_map(|range| clip_range(range, len)).collect());
        self.column_selection = None;
        let primary = primary.and_then(|range| clip_range(range, len)).or_else(|| ranges.last().copied());
        let Some((start, primary_len)) = primary else {
            self.extra_ranges.clear();
            self.anchor = None;
            return;
        };
        ranges.retain(|&range| range != (start, primary_len));
        self.extra_ranges = ranges;
        self.anchor = Some(start);
        self.cursor = start + primary_len;
        self.pending_low_nibble = false;
    }

    /// Make a column selection: the same bytes in each of a run of records.
    pub fn select_column(&mut self, column: ColumnSelection) {
        let Some((start, len)) = clip_range(column.span(), self.document.len()) else { return };
        self.extra_ranges.clear();
        self.column_selection = Some(column);
        self.anchor = Some(start);
        self.cursor = start + len;
        self.pending_low_nibble = false;
    }

    /// Add a range to the selection (Cmd-click), or take it out again when
    /// it is already one of the selected ranges.
    /// The ranges the panel works out are selected as `selection.set`.
    pub fn toggle_selection_range(&mut self, start: usize, len: usize) {
        let mut ranges = self.selection_ranges();
        let primary = if let Some(index) = ranges.iter().position(|&range| range == (start, len)) {
            ranges.remove(index);
            ranges.last().copied()
        } else {
            ranges.push((start, len));
            Some((start, len))
        };
        let cursor = primary.map_or(self.cursor, |(start, len)| start + len);
        if !self.select_as_person(crate::selection_menu::selection_of(ranges), cursor, crate::journal::DerivedFrom::new()) {
            return;
        }
        self.select_matching_packets();
        self.status = self.selection_summary().map_or_else(|| "Nothing selected".to_string(), |summary| format!("Selected {summary}"));
    }

    /// When every selected range is exactly a packet in the packet viewer,
    /// select those packets there too, so both show the same selection.
    fn select_matching_packets(&mut self) {
        let ranges = self.selection_ranges();
        let primary_range = self.selection();
        let state = &mut self.bench.panels.packets;
        let Some(set) = &state.set else { return };
        let index_of = |&(start, len): &(usize, usize)| set.packets.iter().position(|packet| packet.offset == start && packet.len == len);
        let Some(indices) = ranges.iter().map(index_of).collect::<Option<Vec<usize>>>() else { return };
        if indices.is_empty() {
            return;
        }
        let primary = primary_range.and_then(|range| index_of(&range));
        state.selected = indices.into_iter().collect();
        state.focus = primary.or(state.focus);
    }

    /// What a Cmd-click on `offset` adds: the search match there, else the
    /// most specific finding, else the byte itself.
    pub fn range_to_add_at(&mut self, offset: usize) -> (usize, usize) {
        let match_len = self.search_highlight_len();
        if let Some(&at) = self.search_highlights().iter().find(|&&at| offset >= at && offset < at + match_len) {
            return (at, match_len);
        }
        if let Some(finding) = self.pattern_at(offset) {
            return (finding.start, finding.len.min(self.document.len().saturating_sub(finding.start)));
        }
        (offset, 1)
    }

    /// Cmd-click: add what is under `offset` to the selection, or remove it.
    pub fn add_to_selection_at(&mut self, offset: usize) {
        let (start, len) = self.range_to_add_at(offset);
        self.toggle_selection_range(start, len);
    }

    /// Select every match of the Find box in the document, as several ranges.
    /// Select every match of the Find box in the document, as several
    /// ranges: found as `search.find_all`, a page at a time, then selected
    /// as `selection.set`.
    pub fn select_all_matches(&mut self) {
        const MOST_MATCHES: usize = 100_000;
        let Some(needle) = self.search_needle() else { return };
        let Ok(matches) = self.find_all_in_document(MOST_MATCHES) else { return };
        let derived_from = self.all_matches_provenance(&matches);
        let ranges: Vec<(usize, usize)> = matches.into_iter().map(|at| (at, needle.len())).collect();
        if ranges.is_empty() {
            self.status = "No match".to_string();
            return;
        }
        let count = ranges.len();
        let end = ranges.last().map_or(0, |&(at, len)| at + len);
        if !self.select_as_person(crate::selection_menu::selection_of(ranges), end, derived_from) {
            return;
        }
        self.reveal_cursor_centred();
        self.reveal_cursor_in_hex(true);
        self.status = format!("Selected {count} matches");
    }

    /// The range an operation acts on: the selection, or the byte at the cursor.
    fn target_range(&self) -> Option<(usize, usize)> {
        self.selection().or_else(|| (self.cursor < self.document.len()).then_some((self.cursor, 1)))
    }

    pub fn set_cursor(&mut self, position: usize, extend: bool) {
        let position = position.min(self.document.len());
        if extend {
            if self.anchor.is_none() {
                self.anchor = Some(self.cursor);
            }
        } else {
            self.anchor = None;
            self.clear_secondary_selection();
        }
        self.cursor = position;
        self.pending_low_nibble = false;
    }

    /// Start a mouse drag selection on `byte`. With Shift, the drag extends
    /// from the existing selection's anchor instead.
    pub fn begin_drag_selection(&mut self, byte: usize, extend: bool) {
        let grab = if extend { self.anchor.unwrap_or(self.cursor) } else { byte };
        if !extend {
            self.clear_secondary_selection();
        }
        self.drag_column = false;
        self.drag_grab = Some(grab.min(self.document.len().saturating_sub(1)));
        self.drag_selection_to(byte);
    }

    /// Whether a mouse drag is selecting bytes right now.
    pub fn is_dragging(&self) -> bool {
        self.drag_grab.is_some() || self.move_drag.is_some()
    }

    /// Start a drag that adds a range to what is already selected (Cmd held).
    pub fn begin_adding_drag(&mut self, byte: usize) {
        let kept = self.selection_ranges();
        self.begin_drag_selection(byte, false);
        self.extra_ranges = kept;
    }

    /// Start a column drag on `byte` (Alt held): the selection becomes the
    /// same bytes in every record between the drag's corners.
    pub fn begin_column_drag(&mut self, byte: usize) {
        self.clear_secondary_selection();
        self.drag_column = true;
        self.drag_grab = Some(byte.min(self.document.len().saturating_sub(1)));
        self.drag_selection_to(byte);
    }

    /// Select from the drag's starting byte to `byte`, both included.
    pub fn drag_selection_to(&mut self, byte: usize) {
        let Some(grab) = self.drag_grab else { return };
        if self.drag_column {
            if let Some(column) = ColumnSelection::from_corners(self.shape.byte_offset, self.shape.row_stride(), grab, byte) {
                self.select_column(column);
            }
            return;
        }
        let len = self.document.len();
        if byte >= grab {
            self.anchor = Some(grab);
            self.cursor = (byte + 1).min(len);
        } else {
            self.anchor = Some((grab + 1).min(len));
            self.cursor = byte;
        }
        self.pending_low_nibble = false;
    }

    /// Finish a drag. Ending on the byte it started on is a click, not a
    /// selection: the cursor goes to that byte.
    pub fn end_drag_selection(&mut self) {
        self.drag_column = false;
        if let Some(grab) = self.drag_grab.take()
            && self.selection() == Some((grab, 1))
            && self.extra_ranges.is_empty()
        {
            self.anchor = None;
            self.cursor = grab;
            self.column_selection = None;
        }
    }

    /// An arrow or page key: move the cursor `delta` bytes through the
    /// layout, as `cursor.set`, or with Shift extend the selection there,
    /// as `selection.set`.
    pub(crate) fn move_cursor_by(&mut self, delta: i64, extend: bool) {
        // Steps are taken in the layout, so the cursor hops over skipped bytes.
        let view = (self.folds.to_view(self.cursor) as i64 + delta).clamp(0, self.view_len() as i64) as usize;
        let target = self.folds.to_document(view).min(self.document.len());
        self.move_cursor_as_person(target, extend);
        self.scroll_cursor_into_view();
        self.reveal_cursor_in_hex(false);
    }

    pub fn scroll_cursor_into_view(&mut self) {
        let Some((row, _)) = self.shape.pixel_of_byte(self.folds.to_view(self.cursor)) else {
            return;
        };
        let visible = self.visible_rows.max(1);
        if row < self.top_row {
            self.top_row = row;
        } else if row + 1 >= self.top_row + visible {
            self.top_row = row + 2 - visible.min(row + 2);
        }
    }

    /// Scroll the raster so the cursor sits a third of the way down, used when
    /// the cursor jumps from the hex dump or a pattern rather than by keys.
    pub fn reveal_cursor_centred(&mut self) {
        let Some((row, _)) = self.shape.pixel_of_byte(self.folds.to_view(self.cursor)) else {
            return;
        };
        let visible = self.visible_rows.max(1);
        if row < self.top_row || row + 1 >= self.top_row + visible {
            self.top_row = row.saturating_sub(visible / 3);
            self.clamp_top_row();
        }
    }

    // ------------------------------------------------------------------
    // Keeping the raster and the hex dump in step
    // ------------------------------------------------------------------

    /// Bytes per hex dump row.
    pub const HEX_ROW: usize = 16;

    fn hex_max_top(&self) -> usize {
        let total = self.view_len().div_ceil(Self::HEX_ROW).max(1);
        total.saturating_sub(self.hex_visible_rows.max(1) / 2)
    }

    /// Align the hex dump with the raster's top-left byte (after the raster scrolled).
    pub fn sync_hex_to_raster(&mut self) {
        self.hex_top_row = (self.raster_first_view_byte() / Self::HEX_ROW).min(self.hex_max_top());
    }

    /// Scroll the raster so its first row holds the hex dump's first byte (after the hex scrolled).
    pub fn sync_raster_to_hex(&mut self) {
        if let Some((row, _)) = self.shape.pixel_of_byte(self.hex_top_row * Self::HEX_ROW) {
            self.top_row = row;
            self.clamp_top_row();
        }
    }

    /// Scroll the hex dump by whole rows and drag the raster along.
    pub fn scroll_hex_rows(&mut self, delta: i64) {
        self.hex_top_row = (self.hex_top_row as i64 + delta).clamp(0, self.hex_max_top() as i64) as usize;
        self.sync_raster_to_hex();
    }

    /// Make sure the hex dump shows the cursor's row. When `centre` is set the
    /// row is placed a third of the way down (after a click or jump); otherwise
    /// the dump only scrolls when the cursor leaves it (keyboard navigation).
    pub fn reveal_cursor_in_hex(&mut self, centre: bool) {
        let rows = self.hex_visible_rows.max(1);
        let cursor_row = self.folds.to_view(self.cursor) / Self::HEX_ROW;
        let visible = cursor_row >= self.hex_top_row && cursor_row < self.hex_top_row + rows;
        if centre || !visible {
            self.hex_top_row = cursor_row.saturating_sub(rows / 3).min(self.hex_max_top());
        }
    }

    /// View offset of the raster's top-left pixel (see [`Folds`]).
    pub fn raster_first_view_byte(&self) -> usize {
        (self.shape.byte_offset + self.top_row * self.shape.row_stride()).min(self.view_len())
    }

    /// Document offset of the raster's top-left pixel.
    pub fn raster_first_byte(&self) -> usize {
        self.folds.to_document(self.raster_first_view_byte()).min(self.document.len())
    }

    /// Row of the raster that contains document offset `offset`, if it lies
    /// after the origin.
    pub fn raster_row_of(&self, offset: usize) -> Option<usize> {
        self.shape.pixel_of_byte(self.folds.to_view(offset)).map(|(row, _)| row)
    }

    /// Bytes the raster and the hex dump lay out: the document less what is
    /// skipped.
    pub fn view_len(&self) -> usize {
        self.folds.view_len(self.document.len())
    }

    /// Rows the raster has, skipped bytes left out.
    pub fn total_view_rows(&self) -> usize {
        self.shape.total_rows(self.view_len())
    }

    /// The document offset shown at view offset `view`.
    pub fn document_offset(&self, view: usize) -> usize {
        self.folds.to_document(view).min(self.document.len())
    }

    /// Skip the selected ranges (or the byte at the cursor): fold them out of
    /// the raster and the hex dump without deleting anything. A marker shows
    /// where they were; clicking it unfolds them. Carried out as `view.fold`.
    pub fn skip_selection(&mut self) {
        let ranges = self.operation_ranges();
        if ranges.is_empty() {
            self.status = "Select the bytes to skip first".to_string();
            return;
        }
        if self.perform("view.fold", serde_json::json!({ "ranges": ranges })).is_err() {
            return;
        }
        let hidden: usize = ranges.iter().map(|&(_, len)| len).sum();
        let after = ranges.last().map_or(self.cursor, |&(start, len)| start + len).min(self.document.len());
        self.set_cursor(after, false);
        self.clamp_top_row();
        self.sync_hex_to_raster();
        self.status = format!("Skipped {hidden} bytes in {} places; click a marker to show them again", ranges.len());
    }

    /// Show the bytes of the fold starting at `start` again, as `view.unfold`.
    pub fn unfold(&mut self, start: usize) {
        if self.perform("view.unfold", serde_json::json!({ "start": start })).is_ok() {
            self.status = format!("Showing the skipped bytes at {start:#x} again");
        }
    }

    /// Show every skipped range again, as `view.unfold`.
    pub fn unfold_all(&mut self) {
        if self.perform("view.unfold", serde_json::json!({ "all": true })).is_ok() {
            self.status = "Showing every skipped range again".to_string();
        }
    }

    pub fn clamp_top_row(&mut self) {
        let total = self.total_view_rows();
        let max_top = total.saturating_sub(self.visible_rows.max(1) / 2);
        self.top_row = self.top_row.min(max_top);
    }

    pub fn scroll_rows(&mut self, delta_rows: f32) {
        self.scroll_accumulator += delta_rows;
        let whole = self.scroll_accumulator.trunc();
        if whole != 0.0 {
            self.scroll_accumulator -= whole;
            let target = (self.top_row as i64 + whole as i64).max(0) as usize;
            self.top_row = target;
            self.clamp_top_row();
            self.sync_hex_to_raster();
        }
    }

    // ------------------------------------------------------------------
    // Zoom and shape
    // ------------------------------------------------------------------

    pub fn zoom_step(&mut self, direction: i32) {
        let index = ZOOM_LEVELS
            .iter()
            .position(|&level| (level - self.zoom).abs() < 1e-3)
            .unwrap_or_else(|| ZOOM_LEVELS.iter().position(|&level| level > self.zoom).unwrap_or(ZOOM_LEVELS.len() - 1));
        let next = (index as i32 + direction).clamp(0, ZOOM_LEVELS.len() as i32 - 1) as usize;
        self.zoom = ZOOM_LEVELS[next];
    }

    pub fn apply_zoom_delta(&mut self, factor: f32) {
        let target = (self.zoom * factor).clamp(ZOOM_LEVELS[0], ZOOM_LEVELS[ZOOM_LEVELS.len() - 1]);
        // Snap to the nearest level so pixels stay crisp.
        self.zoom = ZOOM_LEVELS
            .iter()
            .copied()
            .min_by(|a, b| (a - target).abs().total_cmp(&(b - target).abs()))
            .unwrap_or(1.0);
    }

    /// The person changes the pixels per row, as `view.set_shape`; a width
    /// outside the allowed range is brought inside it.
    pub fn change_width(&mut self, width: usize) {
        let width = width.clamp(1, MAX_WIDTH);
        let _ = self.perform("view.set_shape", serde_json::json!({ "width": width }));
    }

    /// Set the pixels per row, within the allowed range. For the API and
    /// for widths the app chooses itself; the person's go through
    /// [`ViewerApp::change_width`].
    pub fn set_width(&mut self, width: usize) {
        self.shape.width = width.clamp(1, MAX_WIDTH);
        self.clamp_top_row();
    }

    /// Move the view's origin by `delta` bits, as `view.set_shape`.
    pub(crate) fn adjust_bit_offset(&mut self, delta: i64) {
        let total_bits = (self.shape.byte_offset * 8) as i64 + self.shape.bit_offset as i64 + delta;
        let total_bits = total_bits.clamp(0, (self.document.len() * 8) as i64) as usize;
        self.change_origin(total_bits / 8, (total_bits % 8) as u32);
    }

    /// Make the cursor the top-left pixel of the view, as `view.set_shape`.
    pub fn align_view_to_cursor(&mut self) {
        let offset = self.folds.to_view(self.cursor.min(self.document.len()));
        if self.change_origin(offset, 0) {
            self.top_row = 0;
            self.sync_hex_to_raster();
            self.status = format!("View origin set to {:#x}", self.shape.byte_offset);
        }
    }

    // ------------------------------------------------------------------
    // Editing operations
    // ------------------------------------------------------------------

    pub(crate) fn after_edit(&mut self, cursor: usize) {
        self.cursor = cursor.min(self.document.len());
        self.anchor = None;
        self.clear_secondary_selection();
        self.pending_low_nibble = false;
        self.clamp_top_row();
        self.scroll_cursor_into_view();
        self.reveal_cursor_in_hex(false);
    }

    /// Undo the last step, as `history.undo`.
    pub fn undo(&mut self) {
        if !self.document.can_undo() {
            return;
        }
        if let Some(undone) = self.step_history("history.undo") {
            self.status = undone.label.map_or_else(|| "Undid the last edit".to_string(), |label| format!("Undid {label}"));
        }
    }

    /// Redo the last step undone, as `history.redo`.
    pub fn redo(&mut self) {
        if !self.document.can_redo() {
            return;
        }
        if let Some(redone) = self.step_history("history.redo") {
            self.status = redone.label.map_or_else(|| "Redid the edit".to_string(), |label| format!("Redid {label}"));
        }
    }

    /// Delete every selected range (or the byte at the cursor) as one step.
    pub fn delete_target(&mut self) {
        if self.target_range().is_some() {
            self.apply_operation(Operation::Delete);
            self.scroll_cursor_into_view();
            self.reveal_cursor_in_hex(false);
        }
    }

    /// Backspace: delete the selection, or the byte before the cursor as
    /// `bytes.delete`.
    pub(crate) fn backspace(&mut self) {
        if self.current_selection().is_some() {
            self.delete_target();
        } else if self.cursor > 0 {
            let at = self.cursor.min(self.document.len()) - 1;
            if self.perform("bytes.delete", serde_json::json!({ "start": at, "len": 1 })).is_ok() {
                self.after_edit(at);
            }
        }
    }

    /// Insert `bytes` at the cursor, as `bytes.insert`. Returns whether
    /// they were inserted.
    fn insert_bytes_at_cursor(&mut self, bytes: &[u8]) -> bool {
        let at = self.cursor.min(self.document.len());
        if self.perform("bytes.insert", serde_json::json!({ "at": at, "data": ops::to_compact_hex(bytes) })).is_err() {
            return false;
        }
        self.after_edit(at + bytes.len());
        self.status = format!("Inserted {} bytes at {at:#x}", bytes.len());
        true
    }

    /// Insert the Insert fields' bytes at the cursor.
    pub fn insert_from_fields(&mut self) {
        if let Some(bytes) = self.insert_bytes_from_fields() {
            self.insert_bytes_at_cursor(&bytes);
        }
    }

    /// Fill every selected range (or the cursor byte) with the Fill pattern.
    pub fn fill_target(&mut self) {
        self.fill_selection();
    }

    /// Flip every bit of the selection (or the cursor byte).
    pub fn invert_target(&mut self) {
        self.apply_operation(Operation::Invert);
    }

    pub fn reverse_target(&mut self) {
        self.apply_operation(Operation::Reverse);
    }

    pub fn mirror_target(&mut self) {
        self.apply_operation(Operation::MirrorBits);
    }

    /// Put the view's origin back at the start, as `view.set_shape`.
    pub fn reset_origin(&mut self) {
        if self.change_origin(0, 0) {
            self.top_row = 0;
            self.sync_hex_to_raster();
        }
    }

    /// Apply the best detected period with a pixel format guessed from it,
    /// as one `view.set_shape`: strides divisible by 4 read as RGBA, by 3 as
    /// RGB, otherwise grey.
    pub fn guess_image_shape(&mut self) {
        let Some(best) = self.period_scan.as_ref().and_then(|scan| scan.candidates.first().copied()) else {
            self.start_period_scan();
            self.status = "Scanning for a period first; run Guess image again when the chart appears".to_string();
            return;
        };
        let format = if best.period.is_multiple_of(4) && best.period >= 64 {
            PixelFormat::Rgba8
        } else if best.period.is_multiple_of(3) && best.period >= 48 {
            PixelFormat::Rgb8
        } else {
            PixelFormat::Gray8
        };
        let (width, row_padding) = crate::api::view::width_for_period(format, best.period);
        if self.perform("view.set_shape", serde_json::json!({ "format": format, "width": width, "row_padding": row_padding })).is_ok() {
            self.pan_x = 0.0;
            self.status = format!("Guessed {} at {} bytes per row", format.label(), best.period);
        }
    }

    /// Throw away the current scan so the next frame rescans the view.
    pub fn force_rescan(&mut self) {
        self.pattern_key = None;
        self.patterns.clear();
        self.cursor_structure_key = None;
    }

    // ------------------------------------------------------------------
    // Search
    // ------------------------------------------------------------------

    fn search_needle(&mut self) -> Option<Vec<u8>> {
        match search::needle_for(self.search_mode, &self.search_text, self.search_little_endian) {
            Ok(needle) => Some(needle),
            Err(message) => {
                self.status = message;
                None
            }
        }
    }

    /// Select the match at `at`, as `selection.set`, and show it.
    fn show_match(&mut self, at: usize, len: usize, index_hint: &str) {
        let derived_from = self.match_provenance(at);
        if !self.select_as_person(Some(Selection::Range(at, len)), at + len, derived_from) {
            return;
        }
        self.reveal_cursor_centred();
        self.reveal_cursor_in_hex(true);
        self.status = format!("Match at {at:#x}{index_hint}");
    }

    /// The next match after the selection's start (or the cursor),
    /// wrapping round, found as `search.find` and selected.
    pub fn find_next(&mut self) {
        let Some(needle) = self.search_needle() else { return };
        let from = self.selection().map(|(start, _)| start + 1).unwrap_or(self.cursor);
        let Ok(found) = self.find_in_document(from, false) else { return };
        match found {
            Some(at) => {
                let total = self.search_count.unwrap_or_else(|| search::count_matches(&mut self.document, &needle, 10_000));
                self.search_count = Some(total);
                self.show_match(at, needle.len(), &format!(" ({total} in file)"));
            }
            None => self.status = "No match".to_string(),
        }
    }

    /// The match before the selection (or the cursor), wrapping round,
    /// found as `search.find` and selected.
    pub fn find_previous(&mut self) {
        let Some(needle) = self.search_needle() else { return };
        let before = self.selection().map(|(start, _)| start).unwrap_or(self.cursor);
        let Ok(found) = self.find_in_document(before, true) else { return };
        match found {
            Some(at) => self.show_match(at, needle.len(), ""),
            None => self.status = "No match".to_string(),
        }
    }

    /// Start and length of the bytes search matches are highlighted in: the
    /// raster's visible rows and the hex dump's, capped.
    fn search_highlight_window(&self) -> (usize, usize) {
        let raster_start = self.raster_first_byte();
        let raster_end = self.document_offset(self.raster_first_view_byte() + self.visible_rows.max(1) * self.shape.row_stride());
        let hex_start = self.document_offset(self.hex_top_row * Self::HEX_ROW);
        let hex_end = self.document_offset((self.hex_top_row + self.hex_visible_rows.max(1)) * Self::HEX_ROW);
        let start = raster_start.min(hex_start).min(self.document.len());
        let end = raster_end.max(hex_end).min(self.document.len()).min(start + PATTERN_WINDOW_MAX);
        (start, end.saturating_sub(start))
    }

    /// Where the Find box's needle occurs in and around the visible bytes,
    /// worked out again only when the needle, the view or the bytes change.
    pub fn search_highlights(&mut self) -> &[usize] {
        let needle = if self.search_text.trim().is_empty() {
            None
        } else {
            search::needle_for(self.search_mode, &self.search_text, self.search_little_endian).ok()
        };
        let Some(needle) = needle else {
            self.search_highlight = None;
            return &[];
        };
        let (start, len) = self.search_highlight_window();
        let version = self.document.version();
        let current = self
            .search_highlight
            .as_ref()
            .is_some_and(|cached| cached.version == version && cached.needle == needle && cached.start == start && cached.len == len);
        if !current {
            let bytes = self.document.read_range(start, len + needle.len().saturating_sub(1));
            let matches = search::find_all(&bytes, &needle, crate::legend::MAX_SEARCH_HIGHLIGHTS).into_iter().map(|at| start + at).collect();
            self.search_highlight = Some(SearchHighlight { version, needle, start, len, matches });
        }
        self.search_highlight.as_ref().map_or(&[], |cached| cached.matches.as_slice())
    }

    /// Length of a highlighted search match.
    pub fn search_highlight_len(&self) -> usize {
        self.search_highlight.as_ref().map_or(1, |cached| cached.needle.len().max(1))
    }

    /// Pick out `kind`'s overlays in both views on the next frame.
    pub fn emphasise_layer(&mut self, kind: LayerKind) {
        self.emphasis_next = Some(kind);
    }

    /// The layer being picked out this frame, if the legend points at one.
    pub fn emphasised_layer(&self) -> Option<LayerKind> {
        self.emphasis
    }

    /// Outline `len` bytes at `start` in both views from the next frame,
    /// while a panel's row for them is under the pointer: said on
    /// `view.pointed` at the end of the frame, when it changed.
    pub fn point_at_bytes(&mut self, start: usize, len: usize) {
        self.pointed_next = Some((start, len.max(1)));
    }

    /// The bytes pointed at, as `(start, len)`.
    pub fn pointed_bytes(&self) -> Option<(usize, usize)> {
        self.pointed
    }

    /// Say what the panels pointed at this frame, when it differs from what
    /// the views outline, and start the next frame afresh.
    pub(crate) fn publish_pointed(&mut self) -> bool {
        let pointed = self.pointed_next.take();
        if pointed == self.pointed {
            return false;
        }
        let bytes = pointed.map(|(start, len)| crate::bus::Span { start, len });
        self.publish(crate::bus::window::MAIN_VIEW, Payload::ViewPointed(crate::bus::topics::ViewPointed { bytes }));
        true
    }

    // ------------------------------------------------------------------
    // Bookmarks
    // ------------------------------------------------------------------

    /// Open the naming prompt for a bookmark at the selection or cursor.
    pub fn begin_bookmark(&mut self) {
        let (offset, len) = self.selection().unwrap_or((self.cursor, 0));
        let suggested = self
            .pattern_at(offset)
            .map(|finding| finding.title.clone())
            .unwrap_or_else(|| format!("mark {:#x}", offset));
        self.bookmark_prompt = Some((offset, len, suggested));
    }

    /// Bookmark a byte or span, as `bookmarks.add`.
    pub fn add_bookmark(&mut self, offset: usize, len: usize, name: String) {
        if self.perform("bookmarks.add", serde_json::json!({ "start": offset, "len": len, "name": name })).is_ok() {
            self.status = format!("Bookmarked {name} at {offset:#x}");
        }
    }

    /// Remove the bookmark at `offset`, as `bookmarks.remove`.
    pub fn remove_bookmark(&mut self, offset: usize) {
        let _ = self.perform("bookmarks.remove", serde_json::json!({ "start": offset }));
    }

    /// Select the bookmark at `offset` (or put the cursor on it), as
    /// `selection.set` or `cursor.set`.
    pub fn jump_to_bookmark(&mut self, offset: usize) {
        if let Some(bookmark) = self.bookmarks.at(offset).cloned() {
            let moved = if bookmark.len > 1 {
                self.perform("selection.set", serde_json::json!({ "selection": { "range": [bookmark.offset, bookmark.len] } }))
            } else {
                self.perform("cursor.set", serde_json::json!({ "offset": bookmark.offset }))
            };
            if moved.is_err() {
                return;
            }
            self.reveal_cursor_centred();
            self.reveal_cursor_in_hex(true);
            self.status = format!("Bookmark: {}", bookmark.name);
        }
    }

    pub fn goto_bookmark(&mut self, forward: bool) {
        let here = self.selection().map(|(start, _)| start).unwrap_or(self.cursor);
        let next = if forward { self.bookmarks.next_after(here) } else { self.bookmarks.previous_before(here) };
        match next.map(|b| b.offset) {
            Some(offset) => self.jump_to_bookmark(offset),
            None => self.status = "No bookmarks yet (Cmd+B adds one)".to_string(),
        }
    }

    // ------------------------------------------------------------------
    // Structure at the cursor
    // ------------------------------------------------------------------

    /// Run the registry's parsers at the cursor when it moves, so the
    /// inspector can show a field tree even for things the window scan did
    /// not anchor on.
    fn refresh_cursor_structure(&mut self) {
        /// Bytes read when parsing at the cursor directly.
        const CURSOR_READ: usize = 256 * 1024;
        /// Bytes read when re-parsing a structure the scan found; large enough
        /// for big images and executables that run past the scan window.
        const REPARSE_READ: usize = 16 * 1024 * 1024;
        let key = (self.cursor, self.document.version());
        if self.cursor_structure_key == Some(key) {
            return;
        }
        self.cursor_structure_key = Some(key);
        // The most confident parsed structure covering the cursor, innermost
        // among equals, so a weak chance match cannot hide a real one.
        // Weak findings (chance matches) never stand in as "the" structure.
        let scanned = self
            .patterns_in(self.cursor, self.cursor + 1)
            .filter(|finding| !finding.fields.is_empty() && !finding.weak())
            .min_by(|a, b| b.confidence.total_cmp(&a.confidence).then(a.len.cmp(&b.len)))
            .cloned();
        self.cursor_structure = match scanned {
            Some(finding) => {
                // The scan only saw a window around the view, so its parse can
                // stop short of a large structure. Parse again from the
                // document with a generous read, keeping the same parser.
                let bytes = self.document.read_range(finding.start, REPARSE_READ);
                let reparsed = self.registry.parse_at(&bytes, finding.start).into_iter().find(|f| f.id == finding.id);
                Some(reparsed.filter(|f| f.len >= finding.len).unwrap_or(finding))
            }
            None if self.cursor < self.document.len() => {
                let bytes = self.document.read_range(self.cursor, CURSOR_READ);
                let mut parsed = self.registry.parse_at(&bytes, self.cursor);
                parsed.retain(|finding| !finding.weak());
                parsed.sort_by(|a, b| b.confidence.total_cmp(&a.confidence).then(b.len.cmp(&a.len)));
                parsed.into_iter().next()
            }
            None => None,
        };
        self.publish_cursor_structure();
    }

    /// Publish the structure parsed at the cursor, or withdraw the last one.
    fn publish_cursor_structure(&mut self) {
        const PRODUCER: &str = "tool:cursor-structure";
        let draft = match &self.cursor_structure {
            Some(structure) => self.draft(PRODUCER, Payload::StructureIdentified(structure_of(structure))).span(structure.start, structure.len).confidence(structure.confidence),
            None => self.draft(PRODUCER, Payload::StructureIdentified(StructureIdentified { format: String::new(), title: String::new(), start: 0, len: 0, fields: Vec::new() })).retraction(),
        };
        self.bus.publish(draft);
    }

    /// Media that starts at, or contains, the cursor: findings covering the
    /// cursor are tried first (smallest first), then the selection start,
    /// then the cursor itself. Cached per cursor position and edit.
    pub fn media_at_cursor(&mut self) -> Option<(usize, MediaFormat)> {
        const PROBE_LEN: usize = 64 * 1024;
        let key = (self.cursor, self.document.version());
        if let Some((cached_key, result)) = &self.media_hint
            && *cached_key == key
        {
            return result.clone();
        }
        let mut candidates: Vec<usize> = Vec::new();
        let mut covering: Vec<&Finding> = self.patterns_in(self.cursor, self.cursor + 1).collect();
        covering.sort_by_key(|finding| finding.len);
        candidates.extend(covering.iter().map(|finding| finding.start));
        if let Some((start, _)) = self.selection() {
            candidates.push(start);
        }
        candidates.push(self.cursor);
        candidates.dedup();
        let mut found = None;
        for start in candidates {
            let head = self.document.read_range(start, PROBE_LEN);
            if let Some(format) = media::detect(&head) {
                found = Some((start, format));
                break;
            }
        }
        self.media_hint = Some((key, found.clone()));
        found
    }

    /// Open the media at the cursor in the media window.
    ///
    /// Everything from the media's start to the end of the document is handed
    /// over (capped), because every decoder stops at its format's own end:
    /// PNG at IEND, WAV at its data size, ffmpeg at the container's end.
    /// Lengths from findings are not used: they come from scans of a window
    /// around the view and can stop short of a large file, and a finding that
    /// merely starts at the same offset (such as a high-entropy region) says
    /// nothing about where the media ends.
    pub fn open_media(&mut self) {
        const MAX_MEDIA: usize = 512 * 1024 * 1024;
        let Some((start, format)) = self.media_at_cursor() else {
            self.status = "No image, audio or video starts at the cursor".to_string();
            return;
        };
        let len = (self.document.len() - start).min(MAX_MEDIA);
        let bytes = self.document.read_range(start, len);
        self.status = format!("{} {} at {start:#x}", format.kind.verb(), format.name);
        self.media.open(MediaRequest { format, start, bytes, source_name: self.display_name() });
    }

    /// A texture for the image finding at the cursor, decoded once per image
    /// and document version.
    pub fn image_preview_texture(&mut self, ctx: &Context, finding: &Finding) -> Option<TextureHandle> {
        const PREVIEW_SIZE: u32 = 160;
        let key = (finding.start, self.document.version());
        if let Some((start, version, texture)) = &self.image_preview
            && (*start, *version) == key
        {
            return Some(texture.clone());
        }
        // Read past the finding's length: it may be cut short by the scan window.
        let bytes = self.document.read_range(finding.start, 64 * 1024 * 1024);
        let preview = parsers::image_preview(&bytes, PREVIEW_SIZE)?;
        let image = ColorImage::from_rgba_unmultiplied([preview.width as usize, preview.height as usize], &preview.rgba);
        let texture = ctx.load_texture("image-preview", image, TextureOptions::LINEAR);
        self.image_preview = Some((key.0, key.1, texture.clone()));
        Some(texture)
    }

    /// Right-click menu shared by the raster and the hex dump, for the byte at
    /// `offset` (which becomes the cursor if it is outside the selection).
    pub fn context_menu(&mut self, ui: &mut egui::Ui, offset: usize) {
        let in_selection = self.is_selected(offset);
        if !in_selection && self.cursor != offset {
            self.set_cursor(offset, false);
            self.reveal_cursor_in_hex(true);
        }
        let finding = self.pattern_at(offset).cloned();
        ui.label(RichText::new(format!("{offset:#x}")).monospace().color(theme::TEXT_DIM));
        if let Some((start, format)) = self.media_at_cursor() {
            if ui.button(RichText::new(format!("{} ({} at {start:#x})", format.kind.verb(), format.name)).strong()).clicked() {
                self.open_media();
                ui.close();
            }
            ui.separator();
        }
        if let Some(finding) = &finding {
            ui.label(RichText::new(&finding.title).color(finding.category.colour()));
            if ui.button("Select this finding").clicked() {
                self.select_finding(finding);
                ui.close();
            }
            if finding.category == Category::Compressed && ui.button("Decompress").clicked() {
                self.toggle_compressed_view();
                ui.close();
            }
            ui.separator();
        }
        crate::selection_menu::menu_button(self, ui);
        if let Some((start, _)) = self.folds.fold_containing(offset).or_else(|| self.folds.ranges().first().copied()) {
            if ui.button("Show skipped bytes again").clicked() {
                self.unfold(start);
                ui.close();
            }
            if self.folds.ranges().len() > 1 && ui.button("Show every skipped range").clicked() {
                self.unfold_all();
                ui.close();
            }
        }
        ui.separator();
        ui.menu_button("Analyse", |ui| {
            if ui.add_enabled(self.assistant_available(), egui::Button::new("Ask about this…")).on_disabled_hover_text(crate::assistant::NO_KEY_MESSAGE).clicked() {
                self.dock.open = true;
                self.dock.tab = DockTab::Assistant;
                self.dock.question = format!("What is at {:#x}?", self.selection().map(|(s, _)| s).unwrap_or(offset));
                ui.close();
            }
            if ui.button("Disassemble here").clicked() {
                self.dock.open = true;
                self.dock.tab = DockTab::Disassembly;
                ui.close();
            }
            if ui.button("Apply template here").clicked() {
                let source = self.bench.template_source.clone();
                self.apply_template_here(&source);
                ui.close();
            }
            if ui.add_enabled(self.selection().is_some(), egui::Button::new("Infer template from selection")).clicked() {
                self.infer_template();
                ui.close();
            }
            if ui.button("Statistics of selection").clicked() {
                self.dock.open = true;
                self.dock.tab = DockTab::Statistics;
                crate::analysis_stats::start_statistics(self);
                ui.close();
            }
            if ui.button("Strings in selection").clicked() {
                self.dock.open = true;
                self.dock.tab = DockTab::Strings;
                ui.close();
            }
            if ui.button("Find XOR key for selection").clicked() {
                self.dock.open = true;
                self.dock.tab = DockTab::Xor;
                ui.close();
            }
            if ui.button("Protocol analysis of selection").clicked() {
                self.dock.open = true;
                self.dock.tab = DockTab::Protocol;
                crate::analysis_tools::analyse_protocol(self);
                ui.close();
            }
            if ui.button("Checksums of selection").clicked() {
                self.dock.open = true;
                self.dock.tab = DockTab::Checksums;
                ui.close();
            }
            if ui.button("Plot").clicked() {
                self.open_plot();
                ui.close();
            }
            if ui.button("Play as audio").clicked() {
                self.play_bytes_as_audio();
                ui.close();
            }
        });
        self.packets_context_menu(ui, offset);
        if ui.button("Set view origin here").clicked() {
            self.align_view_to_cursor();
            ui.close();
        }
        if ui.button("Bookmark…").clicked() {
            self.begin_bookmark();
            ui.close();
        }
        if ui.button("Probe for compression").clicked() {
            self.probe_at_cursor();
            ui.close();
        }
        if ui.button("Detect width from here").clicked() {
            self.align_view_to_cursor();
            self.start_period_scan();
            ui.close();
        }
    }

    /// The "Packets" submenu of the right-click menu.
    fn packets_context_menu(&mut self, ui: &mut egui::Ui, offset: usize) {
        let capture = crate::panel_packets::capture_containing(self, offset);
        let has_selection = self.selection().is_some();
        ui.menu_button("Packets", |ui| {
            if ui.add_enabled(has_selection, egui::Button::new("Add selection as packet")).on_disabled_hover_text("Select the packet's bytes first").clicked() {
                crate::panel_packets::add_selection_as_packet(self);
                ui.close();
            }
            if ui.add_enabled(has_selection, egui::Button::new("Split selection by row width")).on_disabled_hover_text("Select the records first").clicked() {
                crate::panel_packets::split_selection_by_row_width(self);
                ui.close();
            }
            if let Some(start) = capture
                && ui.button(format!("Open capture at {start:#x}")).clicked()
            {
                crate::panel_packets::open_capture_at(self, start);
                ui.close();
            }
            if ui.button("Packets from protocol framing").clicked() {
                crate::panel_packets::open_protocol_messages(self);
                ui.close();
            }
        });
    }

    /// Scripted actions registered by plugins (none until a plugin host is attached).
    pub fn plugin_actions(&self) -> Vec<PluginAction> {
        let Some(host) = &self.plugin_host else { return Vec::new() };
        let Ok(host) = host.lock() else { return Vec::new() };
        host.actions()
            .into_iter()
            .map(|action| PluginAction { id: action.id, title: format!("{} ({})", action.title, action.plugin) })
            .collect()
    }

    /// The plugins that declared they edit, by file name.
    pub fn editing_plugins(&self) -> Vec<String> {
        let Some(host) = &self.plugin_host else { return Vec::new() };
        host.try_lock().map(|host| host.editing_plugins()).unwrap_or_default()
    }

    /// Take the methods and subscriptions plugins registered, after they
    /// were loaded or reloaded.
    pub fn refresh_plugin_hooks(&mut self) {
        let Some(host) = &self.plugin_host else { return };
        let Ok(host) = host.lock() else { return };
        self.plugin_methods = host.methods();
        self.plugin_subscriptions = host.subscriptions();
        self.plugin_inbox = Default::default();
        self.journal.note_plugins(crate::journal::plugins_of(&host));
    }

    /// Load one plugin from source, as if from a file called `name`, and
    /// take what it registered: its detectors and the rest, its methods and
    /// its subscriptions.
    pub fn load_plugin_source(&mut self, name: &str, source: &str) -> Result<String, String> {
        let host = Arc::clone(self.plugin_host.get_or_insert_with(|| Arc::new(std::sync::Mutex::new(LuaHost::new()))));
        let summary = host.lock().map_err(|_| "Plugin host is unavailable".to_string())?.load_source(name, source)?;
        self.registry = Arc::new(build_registry_with(Some(&host)));
        self.refresh_plugin_hooks();
        Ok(summary)
    }

    pub fn run_plugin_action(&mut self, id: &str) {
        let Some(host) = self.plugin_host.clone() else {
            self.status = "No plugin host".to_string();
            return;
        };
        let Ok(mut host) = host.lock() else {
            self.status = "Plugin host is unavailable".to_string();
            return;
        };
        let result = host.run_action(id, self);
        for line in host.take_entries() {
            self.status = format!("{}: {}", line.plugin, line.text);
            self.bus.publish(Draft::new(format!("plugin:{}", line.plugin), Payload::PluginLog(line)));
        }
        if let Err(message) = result {
            self.status = format!("Plugin action failed: {message}");
        }
    }

    pub fn reload_plugins(&mut self) {
        let Some(host) = self.plugin_host.clone() else {
            self.status = "No plugin host".to_string();
            return;
        };
        let reports = match host.lock() {
            Ok(mut locked) => locked.reload(),
            Err(_) => {
                self.status = "Plugin host is unavailable".to_string();
                return;
            }
        };
        self.registry = Arc::new(build_registry_with(Some(&host)));
        self.refresh_plugin_hooks();
        self.force_rescan();
        let failed = failed_reports(&reports);
        self.status = if failed.is_empty() {
            format!("Reloaded {} plugin files", reports.len())
        } else {
            format!("Plugins reloaded with errors: {failed}")
        };
    }

    pub fn restore_selection(&mut self, start: usize, len: usize) {
        self.pending_low_nibble = false;
        self.clear_secondary_selection();
        if len > 1 {
            self.anchor = Some(start);
            self.cursor = start + len;
        } else {
            self.anchor = None;
            self.cursor = start;
        }
    }

    /// Cut the selection out and re-insert it `delta` bytes away, as
    /// `bytes.move`, which selects it there.
    pub(crate) fn move_target(&mut self, delta: i64) {
        let Some((start, len)) = self.target_range() else { return };
        let remaining = self.document.len() - len;
        let destination = (start as i64 + delta).clamp(0, remaining as i64) as usize;
        if destination == start {
            return;
        }
        // Counted before the cut: bytes moving right land after the bytes they pass.
        let to = if destination > start { destination + len } else { destination };
        if self.perform("bytes.move", serde_json::json!({ "ranges": [[start, len]], "to": to })).is_ok() {
            self.scroll_cursor_into_view();
            self.status = format!("Moved {len} bytes from {start:#x} to {destination:#x}");
        }
    }

    /// Copy the selected bytes (every range, one after another) as hex.
    pub fn copy(&mut self, ctx: &Context) {
        if self.target_range().is_some() {
            self.clipboard = self.selected_bytes();
            ctx.copy_text(ops::to_hex_string(&self.clipboard));
            self.status = format!("Copied {} bytes", self.clipboard.len());
        }
    }

    pub fn cut(&mut self, ctx: &Context) {
        self.copy(ctx);
        self.delete_target();
    }

    pub fn paste(&mut self, system_text: Option<String>) {
        let bytes = system_text
            .as_deref()
            .and_then(ops::parse_hex)
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| self.clipboard.clone());
        if bytes.is_empty() {
            self.status = "Clipboard is empty".to_string();
            return;
        }
        let data = ops::to_compact_hex(&bytes);
        let pasted = if let Some((start, len)) = self.selection() {
            self.paste_step("bytes.replace", serde_json::json!({ "start": start, "len": len, "data": data }), start + bytes.len())
        } else if self.edit_mode == EditMode::Insert {
            self.insert_bytes_at_cursor(&bytes)
        } else {
            // Overwriting runs on past the end, growing the document there.
            let at = self.cursor.min(self.document.len());
            let fits = self.document.len() - at;
            if bytes.len() <= fits {
                self.paste_step("bytes.write", serde_json::json!({ "start": at, "data": data }), at + bytes.len())
            } else {
                self.paste_step("bytes.replace", serde_json::json!({ "start": at, "len": fits, "data": data }), at + bytes.len())
            }
        };
        if pasted {
            self.status = format!("Pasted {} bytes", bytes.len());
        }
    }

    /// Handle a typed hex digit: overwrite or insert one nibble at the
    /// cursor, as `bytes.write` or `bytes.insert`. The second digit
    /// coalesces with the first, so a typed byte undoes as one step.
    pub(crate) fn type_hex_digit(&mut self, digit: u8) {
        let at = self.cursor.min(self.document.len());
        let at_end = at >= self.document.len();
        if self.pending_low_nibble && !at_end {
            let current = self.document.byte_at(at).unwrap_or(0);
            let data = ops::to_compact_hex(&[(current & 0xF0) | digit]);
            if self.perform("bytes.write", serde_json::json!({ "start": at, "data": data, "coalesce": true })).is_ok() {
                self.pending_low_nibble = false;
                self.cursor = at + 1;
            }
        } else if self.edit_mode == EditMode::Insert || at_end {
            let data = ops::to_compact_hex(&[digit << 4]);
            if self.perform("bytes.insert", serde_json::json!({ "at": at, "data": data })).is_ok() {
                self.pending_low_nibble = true;
            }
        } else {
            let current = self.document.byte_at(at).unwrap_or(0);
            let data = ops::to_compact_hex(&[(digit << 4) | (current & 0x0F)]);
            if self.perform("bytes.write", serde_json::json!({ "start": at, "data": data })).is_ok() {
                self.pending_low_nibble = true;
            }
        }
        self.anchor = None;
        self.scroll_cursor_into_view();
    }

    /// Flip bit `bit` (0 the lowest) of the byte at the cursor, as
    /// `bits.write`.
    pub fn toggle_bit_at_cursor(&mut self, bit: u32) {
        if let Some(byte) = self.document.byte_at(self.cursor) {
            let flipped = if (byte >> bit) & 1 == 1 { "0" } else { "1" };
            let bit_start = self.cursor * 8 + bit as usize;
            let _ = self.perform("bits.write", serde_json::json!({ "bit_start": bit_start, "bits": flipped, "order": "lsb" }));
        }
    }

    /// Go to the offset typed in the Go to field, as `cursor.set`; an
    /// offset past the end goes to the end.
    fn go_to(&mut self) {
        let Some(offset) = ops::parse_offset(&self.goto_text) else {
            self.status = "Go to: enter a decimal or 0x-prefixed hex offset".to_string();
            return;
        };
        let offset = offset.min(self.document.len());
        if self.perform("cursor.set", serde_json::json!({ "offset": offset })).is_ok() {
            self.reveal_cursor_centred();
            self.reveal_cursor_in_hex(true);
            self.status = format!("Cursor at {:#x}", self.cursor);
        }
    }

    /// Select every byte, as `selection.set`.
    pub fn select_all(&mut self) {
        let len = self.document.len();
        self.select_as_person(Some(Selection::Range(0, len)), len, crate::journal::DerivedFrom::new());
    }

    // ------------------------------------------------------------------
    // Compression
    // ------------------------------------------------------------------

    /// The verified compressed stream under the cursor, if any.
    pub fn compressed_stream_at_cursor(&self) -> Option<Finding> {
        self.patterns_in(self.cursor, self.cursor + 1)
            .find(|pattern| pattern.category == Category::Compressed)
            .cloned()
    }

    /// Where a decompression would start: the stream covering the cursor, else
    /// the selection start, else the cursor.
    fn decompress_start(&self) -> usize {
        if let Some(stream) = self.compressed_stream_at_cursor() {
            stream.start
        } else if let Some((start, _)) = self.selection() {
            start
        } else {
            self.cursor
        }
    }

    fn decompress_target(&mut self) -> Result<(usize, Decompressed), String> {
        let start = self.decompress_start();
        if start >= self.document.len() {
            return Err("Nothing to decompress at the end of the document".to_string());
        }
        let input = self.document.read_range(start, DECOMPRESS_INPUT_MAX);
        compress::probe(&input, compress::MEASURE_MAX_OUT)
            .into_iter()
            .next()
            .map(|result| (start, result))
            .ok_or_else(|| format!("Nothing decodes at {start:#x} (tried gzip, zlib, bzip2, xz, zstd, LZ4, raw deflate and lzma)"))
    }

    fn describe_decompression(start: usize, result: &Decompressed) -> String {
        let note = if result.truncated {
            " (cut at the 64 MiB limit)"
        } else if !result.complete {
            " (stream was incomplete)"
        } else {
            ""
        };
        format!(
            "{} at {start:#x}: {} compressed to {} decompressed{note}",
            result.codec.label(),
            compress::human_bytes(result.consumed),
            compress::human_bytes(result.data.len())
        )
    }

    /// Replace the whole view with the decompressed bytes, keeping the current
    /// document on a stack so Back returns to it.
    /// As `codecs.open_decoded`.
    pub fn decompress_to_new_document(&mut self) {
        let start = self.decompress_start();
        if let Ok(result) = self.perform_typed::<crate::api::codecs::OpenDecodedResult>("codecs.open_decoded", serde_json::json!({ "start": start })) {
            self.status = crate::api::codecs::describe_decoded(start, &result);
        }
    }

    /// Open `bytes` as a child of the current document: the current one goes
    /// on the parent stack with its place and analysis, and Back returns to it.
    pub fn open_derived(&mut self, bytes: Vec<u8>, name: String) {
        // Edits so far are said about the parent before it is put away.
        self.publish_edits_as(crate::api::workspace::DOCUMENT_PRODUCER);
        // Named before its document is taken, which would leave it "untitled".
        let parent_name = self.display_name();
        let parent = ParentDocument {
            id: self.document_id.clone(),
            published_version: self.document.version(),
            document: std::mem::take(&mut self.document),
            shape: self.shape,
            cursor: self.cursor,
            top_row: self.top_row,
            name: parent_name,
            patterns: std::mem::take(&mut self.patterns),
            pattern_key: self.pattern_key.take(),
            period_scan: self.period_scan.take(),
            entropy_map: self.entropy_map.take(),
        };
        self.parents.push(parent);
        self.install_document(Document::from_bytes(bytes), Some(name.clone()), Identity::Derived);
        self.status = format!("Opened {name}");
    }

    /// Open `bytes` as a new top-level document (from a URL, device or capture).
    pub fn open_bytes(&mut self, bytes: Vec<u8>, name: String) {
        self.stop_live_sources();
        self.bookmarks = Sidecar::default();
        self.install_document(Document::from_bytes(bytes), Some(name.clone()), Identity::New);
        self.status = format!("Opened {name}");
    }

    /// Replace the document's bytes in place, keeping the view where it was:
    /// for live sources that grow or change underneath the user.
    pub fn refresh_bytes(&mut self, document: Document) {
        let (cursor, anchor, top_row, shape) = (self.cursor, self.anchor, self.top_row, self.shape);
        let name = self.derived_name.clone();
        self.install_document(document, name, Identity::Same);
        self.shape = shape;
        self.shape.byte_offset = self.shape.byte_offset.min(self.document.len());
        self.cursor = cursor.min(self.document.len());
        self.anchor = anchor.map(|a| a.min(self.document.len()));
        self.top_row = top_row;
        self.clamp_top_row();
    }

    /// Move the cursor to `offset` and bring it into view in both panes.
    pub fn jump_to_offset(&mut self, offset: usize) {
        self.set_cursor(offset.min(self.document.len()), false);
        self.reveal_cursor_centred();
        self.reveal_cursor_in_hex(true);
    }

    /// The documents `identity` closes, as (id, name): the one shown unless
    /// it becomes a parent, and for a new document every parent too.
    fn closed_by(&mut self, identity: &Identity) -> Vec<(String, String)> {
        let mut closed = Vec::new();
        if *identity != Identity::Derived {
            closed.push((self.document_id.clone(), self.display_name()));
        }
        if *identity == Identity::New {
            closed.extend(self.parents.drain(..).map(|parent| (parent.id, parent.name)));
        }
        closed
    }

    /// Give the document now shown its id, as `identity` says.
    fn take_identity(&mut self, identity: Identity) {
        self.document_id = match identity {
            Identity::New | Identity::Derived => {
                self.documents_opened += 1;
                format!("doc-{}", self.documents_opened)
            }
            Identity::Back(id) => id,
            Identity::Same => self.document_id.clone(),
        };
    }

    /// Swap the document being viewed and reset everything derived from it.
    fn install_document(&mut self, document: Document, derived_name: Option<String>, identity: Identity) {
        let closed = self.closed_by(&identity);
        self.document = document;
        self.bench.document_changed();
        self.mapped_regions = Arc::default();
        self.derived_name = derived_name;
        let announce = !matches!(identity, Identity::Back(_));
        self.take_identity(identity);
        if announce {
            self.publish_document_replaced(closed);
        } else {
            self.publish_documents_closed(closed);
        }
        self.cursor = 0;
        self.anchor = None;
        self.clear_secondary_selection();
        self.folds.clear();
        self.top_row = 0;
        self.pan_x = 0.0;
        self.shape.byte_offset = 0;
        self.shape.bit_offset = 0;
        self.raster_key = None;
        self.period_scan = None;
        self.patterns.clear();
        self.pattern_key = None;
        self.hex_top_row = 0;
        self.start_entropy_map();
    }

    pub fn back_to_parent(&mut self) {
        let Some(parent) = self.parents.pop() else {
            self.status = "Already at the top-level document".to_string();
            return;
        };
        let name = (!self.parents.is_empty()).then_some(parent.name.clone());
        self.install_document(parent.document, name, Identity::Back(parent.id.clone()));
        // Edits made to it through the API while it waited are said now.
        self.bus_watch.version = parent.published_version;
        self.shape = parent.shape;
        self.cursor = parent.cursor.min(self.document.len());
        self.top_row = parent.top_row;
        self.patterns = parent.patterns;
        self.pattern_key = parent.pattern_key;
        self.period_scan = parent.period_scan;
        if parent.entropy_map.is_some() {
            self.entropy_map = parent.entropy_map;
        }
        // What was known about the parent was forgotten when it was put away.
        self.publish_record_width();
        self.publish_pattern_findings();
        self.clamp_top_row();
        self.reveal_cursor_in_hex(true);
        self.status = format!("Back to {}", parent.name);
    }

    /// Replace the compressed bytes with their decompressed form, as one
    /// undoable edit. Needs an exact stream extent, which zstd and LZ4 cannot
    /// give; those are opened as a new document instead.
    pub fn decompress_in_place(&mut self) {
        match self.decompress_target() {
            Ok((start, result)) => {
                if !result.consumed_exact {
                    self.status = format!(
                        "{} streams have no exact end marker; opening as a new document instead",
                        result.codec.label()
                    );
                    self.decompress_to_new_document();
                    return;
                }
                // The stream's exact extent, found here, is decompressed in
                // place as `transform.apply`, which selects what it made.
                let description = Self::describe_decompression(start, &result);
                let params = serde_json::json!({ "selection": { "range": [start, result.consumed] }, "operation": Operation::Decompress });
                if self.perform("transform.apply", params).is_ok() {
                    self.inplace_codec = Some(result.codec);
                    self.reveal_cursor_centred();
                    self.reveal_cursor_in_hex(true);
                    self.status = format!("Replaced in place: {description}");
                }
            }
            Err(message) => self.status = message,
        }
    }

    /// Compress the selection with the chosen codec, replacing it in place,
    /// as `transform.apply`.
    pub fn compress_selection(&mut self, codec: Codec) {
        let Some((start, len)) = self.selection() else {
            self.status = "Select the bytes to compress first".to_string();
            return;
        };
        let params = serde_json::json!({ "selection": { "range": [start, len] }, "operation": Operation::Compress(codec) });
        let Ok(result) = self.perform_typed::<crate::api::edits::EditResult>("transform.apply", params) else { return };
        let packed_len = result.ranges.first().map_or(0, |&(_, packed)| packed as usize);
        self.status = format!("Compressed {} to {} with {}", compress::human_bytes(len), compress::human_bytes(packed_len), codec.label());
    }

    /// One key flips between the compressed bytes and their contents: inside
    /// a derived document it goes back, otherwise it decompresses here.
    /// Cmd+D: open the stream at the cursor, so nested streams can be
    /// followed down; where no stream is at the cursor in a derived
    /// document, go back to its parent.
    pub fn toggle_compressed_view(&mut self) {
        if self.parents.is_empty() || self.compressed_stream_at_cursor().is_some() {
            self.decompress_to_new_document();
        } else {
            self.go_back_to_parent();
        }
    }

    /// Select exactly the verified stream under the cursor, as
    /// `selection.set`.
    pub fn select_stream_at_cursor(&mut self) {
        if let Some(stream) = self.compressed_stream_at_cursor() {
            self.select_finding(&stream);
        } else {
            self.status = "The cursor is not inside a recognised compressed stream".to_string();
        }
    }

    /// Re-pack the selection with the codec of the last in-place decompression.
    pub fn recompress_selection(&mut self) {
        let codec = self.inplace_codec.unwrap_or(self.compress_codec);
        self.compress_selection(codec);
    }

    /// Bytes of the selection, else of the stream under the cursor.
    fn extract_source(&mut self) -> Option<(usize, Vec<u8>, &'static str)> {
        if let Some((start, len)) = self.selection() {
            return Some((start, self.document.read_range(start, len), "selection"));
        }
        let stream = self.compressed_stream_at_cursor()?;
        Some((stream.start, self.document.read_range(stream.start, stream.len), "stream"))
    }

    /// The span of the selection, else of the stream under the cursor.
    fn extract_span(&self) -> Option<(usize, usize, &'static str)> {
        if let Some((start, len)) = self.selection() {
            return Some((start, len, "selection"));
        }
        let stream = self.compressed_stream_at_cursor()?;
        Some((stream.start, stream.len, "stream"))
    }

    /// Write the selection (or the stream under the cursor) to `path`, as
    /// `documents.export`.
    pub fn export_bytes_to(&mut self, path: &Path) {
        let Some((start, len, what)) = self.extract_span() else {
            self.status = "Select some bytes, or put the cursor in a compressed stream, to extract".to_string();
            return;
        };
        let params = serde_json::json!({ "start": start, "len": len, "path": path.display().to_string() });
        if self.perform("documents.export", params).is_ok() {
            self.status = format!("Saved {} ({} from {start:#x}) to {}", compress::human_bytes(len), what, path.display());
        }
    }

    /// Decompress the block at the cursor straight to `path`, without
    /// opening it, as `documents.export`.
    pub fn export_decompressed_to(&mut self, path: &Path) {
        let start = self.decompress_start();
        let len = self.document.len().saturating_sub(start).min(DECOMPRESS_INPUT_MAX);
        let params = serde_json::json!({ "start": start, "len": len, "path": path.display().to_string(), "decompress": true });
        let Ok(result) = self.perform_typed::<crate::api::documents::ExportResult>("documents.export", params) else { return };
        let Some(stream) = result.decompressed else { return };
        let note = if stream.truncated {
            " (cut at the 64 MiB limit)"
        } else if !stream.complete {
            " (stream was incomplete)"
        } else {
            ""
        };
        self.status = format!(
            "{} at {start:#x}: {} compressed to {} decompressed{note} saved to {}",
            stream.codec.label(),
            compress::human_bytes(stream.consumed as usize),
            compress::human_bytes(result.written as usize),
            path.display()
        );
    }

    /// Copy the selection or stream bytes to the clipboard as hex.
    pub fn copy_extract_as_hex(&mut self, ctx: &Context) {
        if let Some((start, bytes, what)) = self.extract_source() {
            self.clipboard = bytes.clone();
            ctx.copy_text(ops::to_hex_string(&bytes));
            self.status = format!("Copied {} ({what} at {start:#x}) as hex", compress::human_bytes(bytes.len()));
        } else {
            self.status = "Nothing to copy: select bytes or put the cursor in a stream".to_string();
        }
    }

    /// Copy the decompressed contents of the block at the cursor as hex.
    pub fn copy_decompressed_as_hex(&mut self, ctx: &Context) {
        match self.decompress_target() {
            Ok((start, result)) => {
                self.clipboard = result.data.clone();
                ctx.copy_text(ops::to_hex_string(&result.data));
                self.status = format!("Copied: {}", Self::describe_decompression(start, &result));
            }
            Err(message) => self.status = message,
        }
    }

    fn suggested_export_name(&self, suffix: &str) -> String {
        let base = self.display_name().replace([' ', '›', '/'], "_");
        let at = self.selection().map(|(start, _)| start).unwrap_or(self.cursor);
        format!("{base}-{at:#x}{suffix}")
    }

    pub fn export_dialog(&mut self, decompressed: bool) {
        let suffix = if decompressed {
            ".decompressed.bin".to_string()
        } else {
            match self.compressed_stream_at_cursor().filter(|_| self.selection().is_none()) {
                Some(stream) => format!(".{}", stream.title.split(' ').next().unwrap_or("bin")),
                None => ".bin".to_string(),
            }
        };
        let name = self.suggested_export_name(&suffix);
        let dialog = rfd::AsyncFileDialog::new().set_title("Extract bytes to").set_file_name(name);
        self.ask_for_file(DialogKind::Save, dialog, FileAction::Extract { decompressed });
    }

    /// Report every codec that decodes at the cursor without changing anything.
    pub fn probe_at_cursor(&mut self) {
        let start = self.decompress_start();
        let input = self.document.read_range(start, DECOMPRESS_INPUT_MAX);
        let found = compress::probe(&input, 1024 * 1024);
        if found.is_empty() {
            self.status = format!("Nothing decodes at {start:#x}");
        } else {
            let parts: Vec<String> = found
                .iter()
                .map(|r| {
                    format!(
                        "{}: {} to {}{}",
                        r.codec.label(),
                        compress::human_bytes(r.consumed),
                        compress::human_bytes(r.data.len()),
                        if r.truncated { "+" } else { "" }
                    )
                })
                .collect();
            self.status = format!("At {start:#x} decodes as {}", parts.join("; "));
        }
    }

    // ------------------------------------------------------------------
    // Structure analysis (runs on background threads)
    // ------------------------------------------------------------------

    /// The person asks for a scan of the bytes after the view origin for
    /// repeating periods: `analysis.period_scan`, with the window and the
    /// longest period chosen.
    pub fn start_period_scan(&mut self) {
        let start = self.shape.byte_offset.min(self.document.len());
        let params = serde_json::json!({ "start": start, "len": SCAN_WINDOW, "max_period": self.scan_max_period });
        let _ = self.perform("analysis.period_scan", params);
    }

    /// Scan `len` bytes from `start` for periods up to `max_period` on a
    /// thread, as a job of `producer`'s, and show the result in the
    /// structure chart. What `analysis.period_scan` does in the window, and
    /// what the app does by itself when a document opens. Returns the job.
    pub fn scan_periods_from(&mut self, start: usize, len: usize, max_period: usize, producer: &str) -> String {
        let window = self.document.read_range(start, len);
        let sender = self.analysis_tx.clone();
        let job = self.bus.start_job("period-scan", "Period scan", producer, Some((self.document_id(), self.document.version())));
        let id = job.id().to_string();
        thread::spawn(move || match crate::api::analysis::run_period_scan(&window, start, max_period, &job) {
            Some(scan) => drop(sender.send(AnalysisMessage::Periods(scan))),
            None => drop(sender.send(AnalysisMessage::PeriodsCancelled)),
        });
        self.scan_pending = true;
        self.show_panel(Pane::PeriodChart);
        self.status = "Scanning for periods…".to_string();
        id
    }

    /// The scan the app starts by itself, from the view origin.
    fn scan_periods_by_itself(&mut self) {
        let start = self.shape.byte_offset.min(self.document.len());
        self.scan_periods_from(start, SCAN_WINDOW, self.scan_max_period, "tool:period-scan");
    }

    fn start_entropy_map(&mut self) {
        let backing = self.document.original();
        let version = self.document.version();
        let sender = self.analysis_tx.clone();
        let job = self.start_job("entropy", "Entropy strip");
        thread::spawn(move || {
            let map = analysis::entropy_map(backing.as_slice(), ENTROPY_BLOCKS);
            if job.is_cancelled() {
                return job.finish_cancelled();
            }
            job.finish(true, format!("{} blocks", map.len()));
            let _ = sender.send(AnalysisMessage::Entropy { document_version: version, map });
        });
    }

    fn poll_analysis(&mut self, ctx: &Context) {
        while let Ok(message) = self.analysis_rx.try_recv() {
            match message {
                AnalysisMessage::Periods(scan) => {
                    self.status = match scan.candidates.first() {
                        Some(best) => format!("Best period {} bytes", best.period),
                        None => "No repeating period found".to_string(),
                    };
                    self.period_scan = Some(scan);
                    self.scan_pending = false;
                    self.publish_record_width();
                }
                AnalysisMessage::Entropy { map, .. } => self.entropy_map = Some(map),
                AnalysisMessage::PeriodsCancelled => {
                    self.scan_pending = false;
                    self.status = "Period scan cancelled".to_string();
                }
                AnalysisMessage::PatternsCancelled { key } => {
                    if self.pattern_pending == Some(key) {
                        self.pattern_pending = None;
                    }
                    // Not scanned again until the view moves elsewhere.
                    self.pattern_key = Some(key);
                }
                AnalysisMessage::Patterns { key, patterns } => {
                    if self.pattern_pending == Some(key) {
                        self.pattern_pending = None;
                    }
                    self.patterns = patterns;
                    self.pattern_key = Some(key);
                    self.publish_pattern_findings();
                    // New findings can reveal media or structure under the cursor.
                    self.media_hint = None;
                    self.cursor_structure_key = None;
                }
            }
        }
        self.maybe_start_pattern_scan();
        if self.scan_pending || self.pattern_pending.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    /// The region a pattern scan should cover for the current view: the
    /// visible bytes plus a screen either side, aligned to 64 KiB.
    fn wanted_pattern_key(&self) -> Option<PatternKey> {
        let len = self.document.len();
        // Scanned whether or not patterns are highlighted: Findings, the
        // inspector, Decompress and Ask all use what the scan finds.
        if len == 0 {
            return None;
        }
        let stride = self.shape.row_stride();
        let visible_bytes = (self.visible_rows.max(1) * stride).max(4096);
        let first = self.raster_first_byte().min(len);
        let start = (first.saturating_sub(visible_bytes) / PATTERN_ALIGN) * PATTERN_ALIGN;
        let end = (first + 2 * visible_bytes).div_ceil(PATTERN_ALIGN) * PATTERN_ALIGN;
        let end = end.min(len).min(start + PATTERN_WINDOW_MAX);
        Some(PatternKey { version: self.document.version(), start, len: end - start, row_stride: stride })
    }

    fn maybe_start_pattern_scan(&mut self) {
        let Some(key) = self.wanted_pattern_key() else { return };
        if self.pattern_key == Some(key) || self.pattern_pending.is_some() {
            return;
        }
        let window = self.document.read_range(key.start, key.len);
        let mut strides = vec![key.row_stride];
        if let Some(scan) = &self.period_scan {
            strides.extend(scan.candidates.iter().take(3).map(|c| c.period));
        }
        let context = ScanContext { base: key.start, document_len: self.document.len(), strides };
        let sender = self.analysis_tx.clone();
        let registry = Arc::clone(&self.registry);
        let job = self.start_job("pattern-scan", "Pattern scan");
        thread::spawn(move || {
            let mut patterns = registry.scan(&window, &context);
            if job.is_cancelled() {
                job.finish_cancelled();
                let _ = sender.send(AnalysisMessage::PatternsCancelled { key });
                return;
            }
            patterns::resolve_overlaps(&mut patterns);
            job.finish(true, format!("{} findings", patterns.len()));
            let _ = sender.send(AnalysisMessage::Patterns { key, patterns });
        });
        self.pattern_pending = Some(key);
    }

    /// Publish the period scan's best record width, or withdraw the last
    /// one when the scan found none.
    fn publish_record_width(&mut self) {
        const PRODUCER: &str = "tool:period-scan";
        let Some(scan) = &self.period_scan else { return };
        let estimate = scan.candidates.first().map(|best| RecordWidthEstimated {
            width: best.period,
            score: best.score,
            alternatives: scan.candidates.iter().skip(1).take(4).map(|candidate| candidate.period).collect(),
        });
        let draft = match estimate {
            Some(estimate) => self.draft(PRODUCER, Payload::RecordWidthEstimated(estimate)).span(scan.window_start, scan.window_len).confidence(scan.candidates[0].score),
            None => self.draft(PRODUCER, Payload::RecordWidthEstimated(RecordWidthEstimated { width: 0, score: 0.0, alternatives: Vec::new() })).retraction(),
        };
        self.bus.publish(draft);
    }

    /// Publish what the scan of the region around the view found.
    fn publish_pattern_findings(&mut self) {
        let Some(key) = self.pattern_key else { return };
        let findings = FindingsPublished { findings: self.patterns.clone() };
        self.bus.publish(Draft::new("tool:pattern-scan", Payload::FindingsPublished(findings)).about(self.document_id(), key.version).span(key.start, key.len));
    }

    /// Start and length of the region the current findings were scanned from.
    pub fn pattern_scan_region(&self) -> Option<(usize, usize)> {
        self.pattern_key.map(|key| (key.start, key.len))
    }

    pub fn pattern_kind_enabled(&self, category: Category) -> bool {
        self.pattern_kinds[category.index()]
    }

    /// Enabled findings that overlap `[start, end)`.
    pub fn patterns_in(&self, start: usize, end: usize) -> impl Iterator<Item = &Finding> {
        self.patterns
            .iter()
            .chain(self.pinned_findings().into_iter().map(|(_, finding)| finding))
            .filter(move |pattern| self.pattern_kind_enabled(pattern.category) && pattern.start < end && pattern.end() > start)
    }

    /// The most specific enabled finding covering `offset`: smallest span
    /// wins, then the more specific category.
    pub fn pattern_at(&self, offset: usize) -> Option<&Finding> {
        self.patterns_in(offset, offset + 1).min_by_key(|pattern| (pattern.len, pattern.category))
    }

    /// Bring a finding the person has just selected into view, saying on
    /// the status bar what it is. It changes no selection: `select_finding`
    /// selects the finding through `selection.set` first.
    pub(crate) fn reveal_finding(&mut self, pattern: &Finding) {
        let start = pattern.start.min(self.document.len());
        if let Some(row) = self.raster_row_of(start)
            && (row < self.top_row || row >= self.top_row + self.visible_rows)
        {
            self.top_row = row.saturating_sub(self.visible_rows / 3);
            self.clamp_top_row();
        }
        self.reveal_cursor_centred();
        self.reveal_cursor_in_hex(true);
        self.status = pattern.description();
    }

    pub fn pattern_counts(&self) -> [usize; Category::ALL.len()] {
        let mut counts = [0usize; Category::ALL.len()];
        for pattern in &self.patterns {
            counts[pattern.category.index()] += 1;
        }
        counts
    }

    /// Pixels per row and padding bytes that make one row equal `period` bytes.
    pub fn width_for_period(&self, period: usize) -> (usize, usize) {
        crate::api::view::width_for_period(self.shape.format, period)
    }

    /// Make one row `period` bytes long in the current pixel format, as
    /// `view.set_shape`.
    pub fn apply_period(&mut self, period: usize) {
        let (width, row_padding) = self.width_for_period(period);
        let derived_from = self.period_provenance(period, width, row_padding);
        if self.perform_derived("view.set_shape", serde_json::json!({ "width": width, "row_padding": row_padding }), derived_from).is_ok() {
            self.pan_x = 0.0;
            self.status = format!("Width set from a {period} byte period");
        }
    }

    // ------------------------------------------------------------------
    // Texture
    // ------------------------------------------------------------------

    /// Re-rasterise the visible window if anything affecting it changed.
    pub fn ensure_texture(&mut self, ctx: &Context, rows: usize) -> Option<&TextureHandle> {
        let shape = self.shape;
        let rows = rows.clamp(1, (MAX_TEXTURE_PIXELS / shape.width.max(1)).max(1));
        let row_difference = self.row_difference;
        let zoomed_out_colours = self.colours_regions_now().then(|| crate::region_colours::regions_fingerprint(&self.mapped_regions));
        let folds_generation = self.folds.generation();
        let key = RasterKey { version: self.document.version(), shape, top_row: self.top_row, rows, row_difference, zoomed_out_colours, folds_generation };
        if self.raster_key == Some(key) && self.texture.is_some() {
            return self.texture.as_ref();
        }
        let started = Instant::now();
        let stride = shape.row_stride();
        self.fill_raster_bytes(rows);
        let needed = stride * rows + 1;
        let mut pixels = vec![Color32::BLACK; shape.width * rows];
        let bytes = &self.byte_buffer[self.raster_prefix..self.raster_prefix + needed];
        self.value_range = raster::numeric_range(shape.format, bytes, shape.width, rows, stride);
        if zoomed_out_colours.is_some() {
            self.colour_pixels_by_region(rows, &mut pixels);
        } else {
            let style = RasterStyle { format: shape.format, palette: shape.palette, range: self.value_range };
            raster::rasterise_styled(style, bytes, shape.width, rows, stride, &mut pixels);
        }
        let image = ColorImage::new([shape.width, rows], pixels);
        match &mut self.texture {
            Some(texture) => texture.set(image, TextureOptions::NEAREST),
            None => self.texture = Some(ctx.load_texture("raster-view", image, TextureOptions::NEAREST)),
        }
        self.raster_key = Some(key);
        self.last_raster_ms = started.elapsed().as_secs_f32() * 1000.0;
        self.last_raster_pixels = shape.width * rows;
        self.texture.as_ref()
    }

    /// Whether the raster is zoomed out far enough, with the option on, to be
    /// coloured by region instead of by its subsampled bytes.
    pub fn colours_regions_now(&self) -> bool {
        self.colour_regions_when_zoomed_out && self.zoom < 1.0
    }

    /// Colour `rows` rows from the top row by the report's regions, or by
    /// each block's byte class and entropy when no report has been run.
    /// With skipped ranges the layout no longer matches document offsets, so
    /// blocks are coloured from the laid-out bytes rather than the regions.
    fn colour_pixels_by_region(&mut self, rows: usize, pixels: &mut [Color32]) {
        let len = self.view_len();
        if !self.mapped_regions.is_empty() && self.folds.is_empty() {
            crate::region_colours::region_pixels(&self.shape, self.top_row, len, &self.mapped_regions, pixels);
            return;
        }
        let start = self.raster_first_view_byte();
        let mut window = vec![0u8; (self.shape.row_stride() * rows + 1).min(len - start)];
        self.folds.read_view(&mut self.document, start, &mut window);
        crate::region_colours::block_pixels(&self.shape, self.top_row, len, start, &window, pixels);
    }

    /// Read the bytes behind `rows` rows from the top row into
    /// `byte_buffer`, apply the bit shift and the row difference, and record
    /// where the top row starts in the buffer.
    fn fill_raster_bytes(&mut self, rows: usize) {
        let shape = self.shape;
        let stride = shape.row_stride();
        let start = shape.byte_offset + self.top_row * stride;
        // The row difference needs the row above the top one as a reference;
        // above the first row there is nothing, so it compares with zeros.
        let prefix = if self.row_difference.is_active() { stride } else { 0 };
        let needed = prefix + stride * rows + 1;
        self.byte_buffer.clear();
        self.byte_buffer.resize(needed, 0);
        let read_from = if self.top_row > 0 { start - prefix } else { start };
        let skipped = if self.top_row > 0 { 0 } else { prefix };
        self.folds.read_view(&mut self.document, read_from, &mut self.byte_buffer[skipped..]);
        if shape.bit_offset != 0 {
            raster::shift_left_bits(&mut self.byte_buffer[skipped..], shape.bit_offset);
        }
        raster::difference_rows(self.row_difference, &mut self.byte_buffer[..needed - 1], stride);
        self.raster_prefix = prefix;
    }

    /// The bytes the raster was last drawn from, starting at the top row,
    /// after the bit shift and row difference: rows `shape.row_stride()`
    /// bytes apart.
    pub fn raster_bytes(&self) -> &[u8] {
        self.byte_buffer.get(self.raster_prefix..).unwrap_or_default()
    }

    /// Switch to the next row-difference mode.
    pub fn cycle_row_difference(&mut self) {
        self.set_row_difference(self.row_difference.next());
    }

    pub fn set_row_difference(&mut self, mode: RowDifference) {
        self.row_difference = mode;
        self.status = format!("Row difference: {}", mode.label().to_lowercase());
    }

    // ------------------------------------------------------------------
    // Input
    // ------------------------------------------------------------------

    fn handle_shortcuts(&mut self, ctx: &Context) {
        let text_field_focused = ctx.memory(|memory| memory.focused().is_some());

        let cmd = Modifiers::COMMAND;
        let cmd_shift = Modifiers::COMMAND | Modifiers::SHIFT;
        // Global shortcuts work even while a text field has focus.
        if ctx.input_mut(|i| i.consume_key(cmd, Key::O)) {
            self.open_dialog();
        }
        if ctx.input_mut(|i| i.consume_key(cmd_shift, Key::S)) {
            self.save_as_dialog();
        } else if ctx.input_mut(|i| i.consume_key(cmd, Key::S)) {
            self.save();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::N)) {
            self.open_new_document();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::D)) {
            self.toggle_compressed_view();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::E)) {
            self.export_dialog(false);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::Enter)) {
            self.open_media();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::Comma)) {
            self.open_settings();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::J)) {
            self.dock.open = layout::toggle_tools(&mut self.layout);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::L)) {
            self.dock.open = true;
            self.dock.tab = DockTab::Assistant;
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::K)) || ctx.input_mut(|i| i.consume_key(cmd_shift, Key::P)) {
            self.palette.toggle();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::F)) {
            self.focus_search = true;
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::G)) {
            self.focus_goto = true;
        }
        // Shifted bindings first: egui's matching ignores Shift on a binding
        // that does not mention it, so plain F3 would also swallow Shift+F3.
        if ctx.input_mut(|i| i.consume_key(Modifiers::SHIFT, Key::F3)) {
            self.find_previous();
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F3)) {
            self.find_next();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::B)) {
            self.begin_bookmark();
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::SHIFT, Key::F2)) {
            self.goto_bookmark(false);
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F2)) {
            self.goto_bookmark(true);
        }
        if self.palette.open {
            // The palette owns the keyboard while it is open.
            return;
        }
        if self.media.is_open() && !text_field_focused && ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Space)) {
            self.media.toggle_play();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::OpenBracket)) {
            self.go_back_to_parent();
        }
        if text_field_focused {
            return;
        }

        if ctx.input_mut(|i| i.consume_key(cmd_shift, Key::Z)) || ctx.input_mut(|i| i.consume_key(cmd, Key::Y)) {
            self.redo();
        } else if ctx.input_mut(|i| i.consume_key(cmd, Key::Z)) {
            self.undo();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::A)) {
            self.select_all();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::C)) {
            self.copy(ctx);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::X)) {
            self.cut(ctx);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::V)) {
            self.paste(None);
        }
        let pasted_text = ctx.input(|i| {
            i.events.iter().find_map(|event| match event {
                egui::Event::Paste(text) => Some(text.clone()),
                _ => None,
            })
        });
        if let Some(text) = pasted_text {
            self.paste(Some(text));
        }

        let shift = ctx.input(|i| i.modifiers.shift);
        let alt = ctx.input(|i| i.modifiers.alt);
        let stride = self.shape.row_stride() as i64;
        let page = (self.visible_rows.max(2) as i64 - 1) * stride;
        let pixel_bytes = self.shape.format.bytes_per_pixel().max(1) as i64;

        let consume = |key: Key| ctx.input_mut(|i| i.consume_key(Modifiers::NONE, key) || i.consume_key(Modifiers::SHIFT, key));
        if alt && self.current_selection().is_some() {
            // With a selection, Alt+arrows nudge the selected bytes.
            let nudges = [(Key::ArrowLeft, -1), (Key::ArrowRight, 1), (Key::ArrowUp, -stride), (Key::ArrowDown, stride)];
            for (key, delta) in nudges {
                if ctx.input_mut(|i| i.consume_key(Modifiers::ALT, key)) {
                    self.nudge_selection(delta);
                    self.scroll_cursor_into_view();
                    self.reveal_cursor_in_hex(false);
                }
            }
        } else if alt {
            if ctx.input_mut(|i| i.consume_key(Modifiers::ALT, Key::ArrowLeft)) {
                self.adjust_bit_offset(-1);
            }
            if ctx.input_mut(|i| i.consume_key(Modifiers::ALT, Key::ArrowRight)) {
                self.adjust_bit_offset(1);
            }
        } else {
            if consume(Key::ArrowLeft) {
                self.move_cursor_by(-pixel_bytes, shift);
            }
            if consume(Key::ArrowRight) {
                self.move_cursor_by(pixel_bytes, shift);
            }
            if consume(Key::ArrowUp) {
                self.move_cursor_by(-stride, shift);
            }
            if consume(Key::ArrowDown) {
                self.move_cursor_by(stride, shift);
            }
        }
        if consume(Key::PageUp) {
            self.move_cursor_by(-page, shift);
        }
        if consume(Key::PageDown) {
            self.move_cursor_by(page, shift);
        }
        if consume(Key::Home) {
            self.move_cursor_as_person(0, shift);
            self.top_row = 0;
            self.reveal_cursor_in_hex(true);
        }
        if consume(Key::End) {
            let end = self.document.len();
            self.move_cursor_as_person(end, shift);
            self.scroll_cursor_into_view();
            self.reveal_cursor_in_hex(true);
        }
        if consume(Key::M) {
            self.multi_select_mode = !self.multi_select_mode;
        }
        if consume(Key::Escape) && !self.cancel_move_drag() {
            self.clear_selection_as_person();
            self.multi_select_mode = false;
            self.pending_low_nibble = false;
            self.show_help = false;
        }
        if consume(Key::Delete) {
            self.delete_target();
        }
        if consume(Key::Backspace) {
            self.backspace();
        }
        if consume(Key::Insert) {
            self.toggle_edit_mode();
        }
        if consume(Key::OpenBracket) {
            let step = if shift { 16 } else { 1 };
            self.change_width(self.shape.width.saturating_sub(step).max(1));
        }
        if consume(Key::CloseBracket) {
            let step = if shift { 16 } else { 1 };
            self.change_width(self.shape.width + step);
        }
        if consume(Key::Comma) {
            self.adjust_bit_offset(-8);
        }
        if consume(Key::Period) {
            self.adjust_bit_offset(8);
        }
        if consume(Key::H) {
            self.highlight_patterns = !self.highlight_patterns;
        }
        if consume(Key::I) {
            self.insert_dialog_open = true;
        }
        if consume(Key::S) {
            if self.current_selection().is_some() {
                self.skip_selection();
            } else {
                self.status = "Select the bytes to skip first, then press S".to_string();
            }
        }
        if consume(Key::Questionmark) || consume(Key::Slash) || consume(Key::F1) {
            self.show_help = !self.show_help;
        }
        if consume(Key::Minus) {
            self.zoom_step(-1);
        }
        if consume(Key::Plus) || consume(Key::Equals) {
            self.zoom_step(1);
        }

        // Typed hex digits edit the byte under the cursor.
        let typed: Vec<char> = ctx.input(|i| {
            i.events
                .iter()
                .filter_map(|event| match event {
                    egui::Event::Text(text) => Some(text.chars().collect::<Vec<_>>()),
                    _ => None,
                })
                .flatten()
                .collect()
        });
        for character in typed {
            if let Some(digit) = character.to_digit(16) {
                self.type_hex_digit(digit as u8);
            }
        }
    }

    pub fn toggle_edit_mode(&mut self) {
        self.edit_mode = match self.edit_mode {
            EditMode::Overwrite => EditMode::Insert,
            EditMode::Insert => EditMode::Overwrite,
        };
        self.pending_low_nibble = false;
    }

    fn handle_dropped_files(&mut self, ctx: &Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.first().map(|file| file.path().to_path_buf()));
        if let Some(path) = dropped {
            self.open_file(&path);
        }
    }

    // ------------------------------------------------------------------
    // Layout
    // ------------------------------------------------------------------

    fn show_menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("New   Cmd+N").clicked() { self.open_new_document(); ui.close(); }
                if ui.button("Open…   Cmd+O").clicked() { self.open_dialog(); ui.close(); }
                if ui.button("Save   Cmd+S").clicked() { self.save(); ui.close(); }
                if ui.button("Save as…   Shift+Cmd+S").clicked() { self.save_as_dialog(); ui.close(); }
                ui.separator();
                if ui.button("Settings…   Cmd+,").clicked() { self.open_settings(); ui.close(); }
                ui.separator();
                if ui.button("Extract selection or stream to file…   Cmd+E").clicked() { self.export_dialog(false); ui.close(); }
                if ui.button("Extract decompressed contents to file…").clicked() { self.export_dialog(true); ui.close(); }
                if ui.button("Run recipe…").clicked() { self.open_recipe_window(); ui.close(); }
            });
            ui.menu_button("Edit", |ui| {
                if ui.add_enabled(self.document.can_undo(), egui::Button::new(history_item("Undo", self.document.undo_label(), "Cmd+Z"))).clicked() { self.undo(); ui.close(); }
                if ui.add_enabled(self.document.can_redo(), egui::Button::new(history_item("Redo", self.document.redo_label(), "Shift+Cmd+Z"))).clicked() { self.redo(); ui.close(); }
                ui.separator();
                if ui.button("Cut   Cmd+X").clicked() { let ctx = ui.ctx().clone(); self.cut(&ctx); ui.close(); }
                if ui.button("Copy   Cmd+C").clicked() { let ctx = ui.ctx().clone(); self.copy(&ctx); ui.close(); }
                if ui.button("Paste   Cmd+V").clicked() { self.paste(None); ui.close(); }
                if ui.button("Select all   Cmd+A").clicked() { self.select_all(); ui.close(); }
                ui.separator();
                if ui.button("Delete   Backspace").clicked() { self.delete_target(); ui.close(); }
                let mode = match self.edit_mode { EditMode::Overwrite => "Switch to insert mode   Ins", EditMode::Insert => "Switch to overwrite mode   Ins" };
                if ui.button(mode).clicked() { self.toggle_edit_mode(); ui.close(); }
                ui.separator();
                if ui.button("Decompress at cursor, or back up a level   Cmd+D").clicked() { self.toggle_compressed_view(); ui.close(); }
                if ui.button("Select the stream at the cursor").clicked() { self.select_stream_at_cursor(); ui.close(); }
                if ui.button("Decompress here in place").clicked() { self.decompress_in_place(); ui.close(); }
                if ui.button("Probe for compression at cursor").clicked() { self.probe_at_cursor(); ui.close(); }
                ui.menu_button("Compress selection as", |ui| {
                    for codec in Codec::COMPRESSIBLE {
                        if ui.button(codec.label()).clicked() { self.compress_selection(codec); ui.close(); }
                    }
                });
                if ui.add_enabled(!self.parents.is_empty(), egui::Button::new("Back to parent document   Cmd+[")).clicked() { self.go_back_to_parent(); ui.close(); }
            });
            ui.menu_button("Go", |ui| {
                if ui.button("Command palette   Cmd+K").clicked() { self.palette.toggle(); ui.close(); }
                if ui.button("Find…   Cmd+F").clicked() { self.focus_search = true; ui.close(); }
                if ui.button("Find next   F3").clicked() { self.find_next(); ui.close(); }
                if ui.button("Find previous   Shift+F3").clicked() { self.find_previous(); ui.close(); }
                if ui.button("Go to offset…   Cmd+G").clicked() { self.focus_goto = true; ui.close(); }
                if ui.button("Open media at cursor   Cmd+Enter").clicked() { self.open_media(); ui.close(); }
                ui.separator();
                if ui.button("Add bookmark   Cmd+B").clicked() { self.begin_bookmark(); ui.close(); }
                if ui.button("Next bookmark   F2").clicked() { self.goto_bookmark(true); ui.close(); }
                if ui.button("Previous bookmark   Shift+F2").clicked() { self.goto_bookmark(false); ui.close(); }
            });
            ui.menu_button("View", |ui| {
                if ui.button("Zoom in   +").clicked() { self.zoom_step(1); ui.close(); }
                if ui.button("Zoom out   -").clicked() { self.zoom_step(-1); ui.close(); }
                if ui.button("Fit width").clicked() { self.fit_width_requested = true; ui.close(); }
                ui.separator();
                if ui.button("Origin = cursor").clicked() { self.align_view_to_cursor(); ui.close(); }
                if ui.button("Reset origin").clicked() { self.reset_origin(); ui.close(); }
                ui.separator();
                if ui.button("Detect width").clicked() { self.start_period_scan(); ui.close(); }
                if ui.button("Collapse or expand tools   Cmd+J").clicked() { self.dock.open = layout::toggle_tools(&mut self.layout); ui.close(); }
                ui.menu_button("Panels", |ui| {
                    for pane in Pane::all() {
                        let open = self.panel_is_open(pane);
                        let label = if open { format!("✓ {}", pane.title()) } else { format!("   {}", pane.title()) };
                        if ui.button(label).on_hover_text(if open { "Bring forward" } else { "Reopen" }).clicked() {
                            self.show_panel(pane);
                            ui.close();
                        }
                    }
                });
                ui.separator();
                for layout in Layout::ALL {
                    if ui.selectable_label(self.bench.layout == layout, format!("Layout: {}", layout.label())).clicked() {
                        self.bench.layout = layout;
                        ui.close();
                    }
                }
                ui.menu_button("Curve colours", |ui| {
                    for mode in CurveColour::ALL {
                        if ui.selectable_label(self.bench.curve_colour == mode, mode.label()).clicked() {
                            self.bench.curve_colour = mode;
                            ui.close();
                        }
                    }
                });
                ui.checkbox(&mut self.show_pixel_values, "Show values inside pixels when zoomed in")
                    .on_hover_text("Write each byte's hex value inside its pixel once pixels are large enough");
                ui.checkbox(&mut self.colour_regions_when_zoomed_out, "Colour by region when zoomed out")
                    .on_hover_text("Below 1×, show what each part of the file is (report regions, or block class and entropy) instead of subsampled bytes");
                ui.menu_button("Row difference", |ui| {
                    for mode in RowDifference::ALL {
                        if ui.selectable_label(self.row_difference == mode, mode.label()).clicked() {
                            self.set_row_difference(mode);
                            ui.close();
                        }
                    }
                });
                ui.checkbox(&mut self.bench.analysis.show_pointers, "Pointer arrows");
                ui.checkbox(&mut self.bench.show_file_map, "File map");
                if ui.button("Guess image shape").clicked() { self.guess_image_shape(); ui.close(); }
                ui.separator();
                if ui.button("Reload plugins").clicked() { self.reload_plugins_by_hand(); ui.close(); }
            });
            ui.menu_button("Layout", |ui| {
                layouts::show_layout_menu(self, ui);
                ui.separator();
                ui.label(RichText::new("Drag a tab to any edge to split, onto another pane to stack it, or out to float it. Closed panels reopen from View › Panels.").small().color(theme::TEXT_DIM));
                ui.separator();
                if ui.add_enabled(self.toolbar_rows.is_some(), egui::Button::new("Arrange toolbar automatically"))
                    .on_hover_text("Forget the order you dragged the toolbar groups into and pack them into the fewest rows")
                    .clicked()
                {
                    self.set_toolbar_rows(None);
                    ui.close();
                }
                ui.label(RichText::new("Drag a toolbar group by its caption or edge to move it.").small().color(theme::TEXT_DIM));
            });
            ui.menu_button("Tools", |ui| {
                if ui.button("Explain this file").clicked() { self.dock.open = true; self.dock.tab = DockTab::Report; self.explain_file(); ui.close(); }
                if ui.button("Reference for the format at the cursor").clicked() { self.dock.toggle(DockTab::Reference); ui.close(); }
                if ui.button("History: undo, go back, play back, save as recipe").clicked() { self.dock.toggle(DockTab::History); ui.close(); }
                if ui.button("Structure map: segments, find similar, feature tracks").clicked() { self.dock.toggle(DockTab::StructureMap); ui.close(); }
                if ui.button("Dot plot (self-similarity)").clicked() { self.dock.toggle(DockTab::DotPlot); ui.close(); }
                if ui.button("Trigram cube").clicked() { self.dock.toggle(DockTab::Trigrams); ui.close(); }
                if ui.button("Size map").clicked() { self.dock.toggle(DockTab::SizeMap); ui.close(); }
                if ui.button("Find images").clicked() { self.dock.toggle(DockTab::Images); ui.close(); }
                if ui.button("Firmware: processor, load address, vectors").clicked() { self.dock.toggle(DockTab::Firmware); ui.close(); }
                if self.assistant_available() {
                    if ui.button("Ask about this file…   Cmd+L").clicked() { self.dock.open = true; self.dock.tab = DockTab::Assistant; ui.close(); }
                    if ui.button("Characterise with Ask").clicked() { self.characterise_with_ask(); ui.close(); }
                } else {
                    ui.add_enabled(false, egui::Button::new("Ask about this file…   Cmd+L")).on_disabled_hover_text(crate::assistant::NO_KEY_MESSAGE);
                    if ui.button("Add API key to enable Ask…").clicked() { self.open_settings(); ui.close(); }
                }
                if ui.button("Template…").clicked() { self.dock.toggle(DockTab::Template); ui.close(); }
                if ui.button("Infer a template from the selection").clicked() { self.infer_template(); ui.close(); }
                if ui.button("Disassemble at cursor").clicked() { self.dock.open = true; self.dock.tab = DockTab::Disassembly; ui.close(); }
                if ui.button("Unpack everything").clicked() { self.dock.open = true; self.dock.tab = DockTab::Unpacked; self.start_unpack(); ui.close(); }
                if ui.button("Filesystems and block types").clicked() { self.dock.toggle(DockTab::Forensics); ui.close(); }
                if ui.button("Checksums").clicked() { self.dock.toggle(DockTab::Checksums); ui.close(); }
                ui.separator();
                if ui.button("Characterise: codecs, media streams, text").clicked() { self.dock.toggle(DockTab::Characterise); ui.close(); }
                if ui.button("Learn a format, fuzzy match").clicked() { self.dock.toggle(DockTab::Learn); ui.close(); }
                if ui.button("Byte statistics").clicked() { self.dock.open = true; self.dock.tab = DockTab::Statistics; crate::analysis_stats::start_statistics(self); ui.close(); }
                if ui.button("Strings").clicked() { self.dock.toggle(DockTab::Strings); ui.close(); }
                if ui.button("Record columns").clicked() { self.dock.toggle(DockTab::Columns); ui.close(); }
                if ui.button("Bits and encodings").clicked() { self.dock.toggle(DockTab::Bits); ui.close(); }
                if ui.button("Protocol analysis").clicked() { self.dock.open = true; self.dock.tab = DockTab::Protocol; crate::analysis_tools::analyse_protocol(self); ui.close(); }
                if ui.button("Packet viewer").clicked() { self.dock.toggle(DockTab::Packets); ui.close(); }
                if ui.button("XOR keys").clicked() { self.dock.toggle(DockTab::Xor); ui.close(); }
                if ui.button("Crypto: encrypted blocks, keys, ciphers").clicked() { self.dock.toggle(DockTab::Crypto); ui.close(); }
                if ui.button("Compare many files…").clicked() { self.dock.toggle(DockTab::Compare); ui.close(); }
                if ui.button("Compare with file…").clicked() {
                    self.dock.open = true;
                    self.dock.tab = DockTab::Diff;
                    self.ask_for_file(DialogKind::Open, rfd::AsyncFileDialog::new().set_title("Compare with"), FileAction::Compare);
                    ui.close();
                }
                ui.separator();
                if ui.button("Plot selection").clicked() { self.open_plot(); ui.close(); }
                if ui.button("Play selection as audio").clicked() { self.play_bytes_as_audio(); ui.close(); }
                ui.menu_button("Audio format", |ui| {
                    for format in crate::plot::PcmFormat::ALL {
                        ui.selectable_value(&mut self.bench.pcm_format, format, format.label());
                    }
                    ui.separator();
                    for rate in [8000u32, 11_025, 22_050, 44_100, 48_000] {
                        ui.selectable_value(&mut self.bench.pcm_rate, rate, format!("{rate} Hz"));
                    }
                    ui.separator();
                    ui.selectable_value(&mut self.bench.pcm_channels, 1, "Mono");
                    ui.selectable_value(&mut self.bench.pcm_channels, 2, "Stereo");
                });
                ui.separator();
                if ui.button("Open URL, device or serial port…").clicked() { self.dock.open = true; self.dock.tab = DockTab::Live; ui.close(); }
                let mut watching = self.bench.watch_enabled;
                if ui.checkbox(&mut watching, "Watch file for changes").changed() { self.set_watch(watching); }
            });
            ui.menu_button("Help", |ui| {
                if ui.button("Keyboard shortcuts   ?").clicked() { self.show_help = true; ui.close(); }
            });
        });
    }

    fn show_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(2.0);
        let mut packer = RowPacker::begin(ui, "toolbar", self.toolbar_rows.as_deref());
        packer.captioned(ui, "format", "Format", |ui| {
            let mut format = self.shape.format;
            egui::ComboBox::from_id_salt("pixel-format")
                .selected_text(format.label())
                .width(132.0)
                .show_ui(ui, |ui| {
                    for choice in PixelFormat::ALL {
                        ui.selectable_value(&mut format, choice, choice.label());
                    }
                })
                .response
                .on_hover_text("How bytes become pixels");
            if format != self.shape.format {
                self.change_format(format);
            }
            if self.shape.format.uses_palette() {
                egui::ComboBox::from_id_salt("palette")
                    .selected_text(self.shape.palette.label())
                    .width(90.0)
                    .show_ui(ui, |ui| {
                        for palette in Palette::ALL {
                            ui.selectable_value(&mut self.shape.palette, palette, palette.label());
                        }
                    })
                    .response
                    .on_hover_text("Colour ramp for single-channel formats");
            }
            let mut row_difference = self.row_difference;
            egui::ComboBox::from_id_salt("row-difference")
                .selected_text(row_difference.short_label())
                .width(54.0)
                .show_ui(ui, |ui| {
                    for mode in RowDifference::ALL {
                        ui.selectable_value(&mut row_difference, mode, mode.label());
                    }
                })
                .response
                .on_hover_text("Row difference: compare each row with the one above.\nFields that repeat in every record go dark; fields that change stand out.");
            if row_difference != self.row_difference {
                self.set_row_difference(row_difference);
            }
        });

        packer.captioned(ui, "width", "Width (pixels per row)", |ui| {
            ui.spacing_mut().slider_width = 120.0;
            let mut width = self.shape.width;
            let slider = ui.add(
                egui::Slider::new(&mut width, 1..=4096)
                    .logarithmic(true)
                    .clamping(egui::SliderClamping::Never)
                    .show_value(false),
            );
            let drag = ui.add(egui::DragValue::new(&mut width).range(1..=MAX_WIDTH).speed(1.0));
            if slider.changed() || drag.changed() {
                self.change_width(width);
            }
            slider.on_hover_text("Drag to find the stride of repeating structures.\n[ and ] step by 1, Shift for 16");
            ui.menu_button("Presets", |ui| {
                ui.label(RichText::new("Common widths").small().color(theme::TEXT_DIM));
                ui.horizontal_wrapped(|ui| {
                    for width in [8usize, 16, 32, 64, 128, 256, 320, 512, 640, 1024, 2048] {
                        if ui.small_button(width.to_string()).clicked() {
                            self.change_width(width);
                            ui.close();
                        }
                    }
                });
                ui.separator();
                ui.label(RichText::new("Image layouts").small().color(theme::TEXT_DIM));
                let layouts: [(&str, PixelFormat, usize); 8] = [
                    ("QVGA 320 grey", PixelFormat::Gray8, 320),
                    ("QVGA 320 RGB565", PixelFormat::Rgb565, 320),
                    ("VGA 640 RGB", PixelFormat::Rgb8, 640),
                    ("VGA 640 RGBA", PixelFormat::Rgba8, 640),
                    ("HD 1280 RGBA", PixelFormat::Rgba8, 1280),
                    ("1-bit 128 (LCD)", PixelFormat::Bit1Msb, 128),
                    ("Byte class 256", PixelFormat::ByteClass, 256),
                    ("Tiles 8 px 1-bit", PixelFormat::Bit1Msb, 8),
                ];
                for (label, format, width) in layouts {
                    if ui.button(label).clicked() {
                        self.apply_image_layout(format, width);
                        ui.close();
                    }
                }
                ui.separator();
                if ui.button("Guess image shape").on_hover_text("Use the detected period and a format that divides it").clicked() {
                    self.guess_image_shape();
                    ui.close();
                }
            });
            ui.label(RichText::new(format!("{} B/row", self.shape.row_bytes())).color(theme::TEXT_DIM));
            ui.label(RichText::new("pad").color(theme::TEXT_DIM));
            let mut row_padding = self.shape.row_padding;
            let padding = ui
                .add(egui::DragValue::new(&mut row_padding).range(0..=crate::api::view::MAX_ROW_PADDING).suffix(" B"))
                .on_hover_text("Bytes skipped after each row (for row headers or stride padding)");
            if padding.changed() {
                self.change_row_padding(row_padding);
            }
        });

        packer.captioned(ui, "origin", "Origin", |ui| {
            let max_offset = self.document.len();
            let (mut byte_offset, mut bit_offset) = (self.shape.byte_offset, self.shape.bit_offset);
            let byte = ui
                .add(egui::DragValue::new(&mut byte_offset).range(0..=max_offset).speed(1.0).prefix("byte "))
                .on_hover_text("Document offset shown at the top-left pixel\n, and . step by one byte");
            let bit = ui.add(egui::DragValue::new(&mut bit_offset).range(0..=7).prefix("bit ")).on_hover_text("Extra bit shift\nAlt+Left / Alt+Right step by one bit");
            if byte.changed() || bit.changed() {
                self.change_origin(byte_offset, bit_offset);
            }
            if ui.button("To cursor").on_hover_text("Make the cursor the top-left pixel").clicked() {
                self.align_view_to_cursor();
            }
        });

        packer.captioned(ui, "zoom", "Zoom", |ui| {
            if ui.button("-").clicked() {
                self.zoom_step(-1);
            }
            ui.label(RichText::new(format!("{}×", self.zoom)).monospace());
            if ui.button("+").clicked() {
                self.zoom_step(1);
            }
            if ui.button("Fit").on_hover_text("Set the width to fill the view").clicked() {
                self.fit_width_requested = true;
            }
        });

        packer.captioned(ui, "goto", "Go to", |ui| {
            let goto = ui.add(egui::TextEdit::singleline(&mut self.goto_text).desired_width(90.0).hint_text("0x1F4 or 500"));
            if self.focus_goto {
                goto.request_focus();
                self.focus_goto = false;
            }
            if goto.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                self.go_to();
            }
            if ui.button("Go").clicked() {
                self.go_to();
            }
        });

        packer.captioned(ui, "find", "Find", |ui| {
            egui::ComboBox::from_id_salt("search-mode")
                .selected_text(self.search_mode.label())
                .width(70.0)
                .show_ui(ui, |ui| {
                    for mode in SearchMode::ALL {
                        if ui.selectable_value(&mut self.search_mode, mode, mode.label()).changed() {
                            self.search_count = None;
                        }
                    }
                });
            let field = ui.add(egui::TextEdit::singleline(&mut self.search_text).desired_width(140.0).hint_text("bytes, text or number"));
            if self.focus_search {
                field.request_focus();
                self.focus_search = false;
            }
            if field.changed() {
                self.search_count = None;
            }
            if field.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                self.find_next();
            }
            if ui.button("Next").on_hover_text("F3").clicked() {
                self.find_next();
            }
            if ui.button("Prev").on_hover_text("Shift+F3").clicked() {
                self.find_previous();
            }
            if ui.button("All matches").on_hover_text("Select every match at once, as several ranges, to change them all together").clicked() {
                self.select_all_matches();
            }
            if self.search_mode == SearchMode::Integer {
                ui.checkbox(&mut self.search_little_endian, "LE");
            }
        });

        packer.captioned(ui, "insert", "Insert at cursor", |ui| {
            ui.add(egui::DragValue::new(&mut self.insert_count).range(1..=usize::MAX / 2).speed(1.0).suffix(" ×"))
                .on_hover_text("How many bytes to insert");
            ui.add(egui::TextEdit::singleline(&mut self.insert_value_text).desired_width(70.0).hint_text("hex pattern"))
                .on_hover_text("Byte pattern to repeat, e.g. 00 or DE AD");
            if ui.button("Insert").clicked() {
                self.insert_from_fields();
            }
        });

        let has_target = self.target_range().is_some();
        let selection_caption = crate::selection_menu::menu_title(self);
        packer.captioned(ui, "selection", &selection_caption, |ui| {
            ui.toggle_value(&mut self.multi_select_mode, "Multi-select")
                .on_hover_text("Clicks and drags add sections to the selection; click a section again to take it out. M toggles it; Esc clears the sections and leaves.");
            ui.add_enabled_ui(has_target, |ui| {
                if ui.button(RichText::new("Delete").color(theme::DANGER)).on_hover_text("Backspace / Del").clicked() {
                    self.delete_target();
                }
                ui.add(egui::TextEdit::singleline(&mut self.fill_value_text).desired_width(60.0).hint_text("hex"))
                    .on_hover_text("Pattern for Fill");
                if ui.button("Fill").on_hover_text("Overwrite with the pattern").clicked() {
                    self.fill_target();
                }
                if ui.button("Invert").on_hover_text("Flip every bit").clicked() {
                    self.invert_target();
                }
                if ui.button("Reverse").on_hover_text("Reverse byte order").clicked() {
                    self.reverse_target();
                }
                if ui.button("Mirror bits").on_hover_text("Reverse the bits within each byte").clicked() {
                    self.mirror_target();
                }
                ui.menu_button("More", |ui| crate::selection_menu::show_selection_menu(self, ui))
                    .response
                    .on_hover_text("Every operation: insert, XOR, add, shift and rotate bits, swap byte order, number, move, duplicate, skip, copy as…");
            });
        });

        packer.captioned(ui, "shift", "Shift bits", |ui| {
            ui.add_enabled_ui(has_target, |ui| {
                if ui.button("◀").on_hover_text("Shift bits towards the start").clicked() {
                    self.apply_operation(Operation::ShiftBits(self.shift_amount));
                }
                ui.add(egui::DragValue::new(&mut self.shift_amount).range(1..=i64::MAX / 4).suffix(" bits"));
                if ui.button("▶").on_hover_text("Shift bits towards the end").clicked() {
                    self.apply_operation(Operation::ShiftBits(-self.shift_amount));
                }
            });
        });

        packer.captioned(ui, "move", "Move", |ui| {
            ui.add_enabled_ui(has_target, |ui| {
                if ui.button("◀").on_hover_text("Move the bytes towards the start").clicked() {
                    self.move_target(-self.move_amount);
                }
                ui.add(egui::DragValue::new(&mut self.move_amount).range(1..=i64::MAX / 4).suffix(" B"));
                if ui.button("▶").on_hover_text("Move the bytes towards the end").clicked() {
                    self.move_target(self.move_amount);
                }
            });
        });

        packer.captioned(ui, "typing", "Typing", |ui| {
            let (label, hint) = match self.edit_mode {
                EditMode::Overwrite => ("Overwrite", "Typed hex replaces bytes. Press Insert to switch."),
                EditMode::Insert => ("Insert", "Typed hex inserts new bytes. Press Insert to switch."),
            };
            if ui.selectable_label(self.edit_mode == EditMode::Insert, label).on_hover_text(hint).clicked() {
                self.toggle_edit_mode();
            }
            ui.add_enabled_ui(self.document.can_undo(), |ui| {
                if ui.button("Undo").on_hover_text(history_item("Undo", self.document.undo_label(), "Cmd+Z")).clicked() {
                    self.undo();
                }
            });
            ui.add_enabled_ui(self.document.can_redo(), |ui| {
                if ui.button("Redo").on_hover_text(history_item("Redo", self.document.redo_label(), "Shift+Cmd+Z")).clicked() {
                    self.redo();
                }
            });
        });

        packer.captioned(ui, "analysis", "Analysis", |ui| {
            let enabled = !self.document.is_empty();
            if ui.add_enabled(enabled, egui::Button::new("Detect width"))
                .on_hover_text("Find repeating periods after the view origin and suggest widths")
                .clicked()
            {
                self.start_period_scan();
            }
            if ui.selectable_label(self.panel_is_open(Pane::PeriodChart), "Chart").on_hover_text("Show the period chart").clicked() {
                self.toggle_panel(Pane::PeriodChart);
            }
            ui.separator();
            if ui
                .selectable_label(self.highlight_patterns, "Patterns")
                .on_hover_text("Highlight counters, timestamps, text, signatures and more (H). They are detected either way and listed in Findings; choose the default in Settings.")
                .clicked()
            {
                self.highlight_patterns = !self.highlight_patterns;
            }
            let counts = self.pattern_counts();
            ui.menu_button("Kinds", |ui| {
                for category in Category::ALL {
                    if counts[category.index()] == 0 && !self.pattern_kinds[category.index()] {
                        continue;
                    }
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(10.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, 2.0, category.colour());
                        ui.checkbox(&mut self.pattern_kinds[category.index()], format!("{} ({})", category.label(), counts[category.index()]));
                    });
                }
                ui.separator();
                if ui.button("All").clicked() {
                    self.pattern_kinds = [true; Category::ALL.len()];
                }
                if ui.button("None").clicked() {
                    self.pattern_kinds = [false; Category::ALL.len()];
                }
            });
            ui.add_visible(self.pattern_pending.is_some(), egui::Spinner::new().size(14.0))
                .on_hover_text("Scanning the visible region");
        });

        if let Some((start, format)) = self.media_at_cursor() {
            packer.captioned(ui, "media", &format!("Media: {} at {start:#x}", format.name), |ui| {
                if ui.button(RichText::new(format.kind.verb()).strong()).on_hover_text("Cmd+Enter").clicked() {
                    self.open_media();
                }
            });
        }

        let stream = self.compressed_stream_at_cursor();
        let caption = match &stream {
            Some(pattern) => format!("Compression: {}", pattern.description().split(" compressed").next().unwrap_or("stream")),
            None => "Compression".to_string(),
        };
        packer.captioned(ui, "compression", &caption, |ui| {
            let has_data = !self.document.is_empty();
            // Decompressing works in any document, a derived one included,
            // so streams nested in streams can be followed down; Back climbs
            // out again.
            ui.add_enabled_ui(has_data, |ui| {
                if ui.button("Decompress").on_hover_text("Open the decompressed block as a new document (Cmd+D)").clicked() {
                    self.decompress_to_new_document();
                }
            });
            if let Some(parent) = self.parents.last() {
                let hint = format!("Return to {} (Cmd+D where no stream is at the cursor)", parent.name);
                if ui.button("Back out").on_hover_text(hint).clicked() {
                    self.go_back_to_parent();
                }
            }
            ui.add_enabled_ui(has_data, |ui| {
                if ui.button("In place").on_hover_text("Replace the compressed block with its contents (undoable)").clicked() {
                    self.decompress_in_place();
                }
                if let Some(codec) = self.inplace_codec {
                    let label = format!("Re-pack as {}", codec.label());
                    ui.add_enabled_ui(self.selection().is_some(), |ui| {
                        if ui.button(label).on_hover_text("Compress the selection with the codec it was unpacked from (undoable)").clicked() {
                            self.recompress_selection();
                        }
                    });
                }
                if ui.button("Probe").on_hover_text("Report which codecs decode at the cursor").clicked() {
                    self.probe_at_cursor();
                }
                if stream.is_some() && ui.button("Select stream").on_hover_text("Select exactly the compressed bytes").clicked() {
                    self.select_stream_at_cursor();
                }
            });
            ui.separator();
            let ctx = ui.ctx().clone();
            ui.menu_button("Extract", |ui| {
                let what = if self.selection().is_some() { "selection" } else { "stream at cursor" };
                if ui.button(format!("Save {what} to file…   Cmd+E")).clicked() { self.export_dialog(false); ui.close(); }
                if ui.button("Save decompressed contents to file…").clicked() { self.export_dialog(true); ui.close(); }
                ui.separator();
                if ui.button(format!("Copy {what} as hex")).clicked() { self.copy_extract_as_hex(&ctx); ui.close(); }
                if ui.button("Copy decompressed contents as hex").clicked() { self.copy_decompressed_as_hex(&ctx); ui.close(); }
            });
            ui.separator();
            ui.add_enabled_ui(self.selection().is_some(), |ui| {
                egui::ComboBox::from_id_salt("compress-codec")
                    .selected_text(self.compress_codec.label())
                    .width(90.0)
                    .show_ui(ui, |ui| {
                        for codec in Codec::COMPRESSIBLE {
                            ui.selectable_value(&mut self.compress_codec, codec, codec.label());
                        }
                    });
                if ui.button("Compress selection").on_hover_text("Replace the selection with its compressed form (undoable)").clicked() {
                    self.compress_selection(self.compress_codec);
                }
            });
        });
        if let Some(rows) = packer.finish(ui) {
            self.set_toolbar_rows(Some(rows));
        }
        ui.add_space(2.0);
    }

    fn show_status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let dim = theme::TEXT_DIM;
            if self.document.is_modified() {
                ui.label(RichText::new("●").color(theme::CURSOR)).on_hover_text("Unsaved changes");
            }
            if !self.parents.is_empty()
                && ui.button("Back").on_hover_text("Return to the document this was decompressed from (Cmd+[)").clicked()
            {
                self.go_back_to_parent();
            }
            ui.label(RichText::new(self.display_name()).strong());
            ui.label(RichText::new(human_size(self.document.len())).color(dim));
            ui.separator();
            ui.label(RichText::new("cursor").color(dim));
            ui.monospace(format!("{:#x}", self.cursor));
            if self.multi_select_mode {
                ui.separator();
                let sections = self.current_selection().map_or(0, |selected| selected.ranges(self.document.len()).len());
                ui.label(RichText::new(format!("Multi-select · {sections} sections · Esc to finish")).color(theme::ACCENT).strong())
                    .on_hover_text("Clicks and drags add sections; click a section again to take it out. M or the toolbar button turns this off.");
            }
            self.show_layout_suggestion(ui);
            if let Some(selected) = self.current_selection() {
                let (start, len) = selected.span();
                ui.separator();
                ui.label(RichText::new("selection").color(dim));
                ui.monospace(format!("{start:#x}–{:#x}", start + len));
                ui.label(RichText::new(selected.describe(self.document.len())).color(dim));
            }
            if let Some((offset, byte)) = self.hover.and_then(|offset| self.document.byte_at(offset).map(|byte| (offset, byte))) {
                ui.separator();
                ui.label(RichText::new("hover").color(dim));
                ui.monospace(format!("{offset:#x} = {byte:02X}"));
                if let Some(pattern) = self.pattern_at(offset) {
                    ui.label(RichText::new(pattern.description()).color(pattern.category.colour()));
                }
            }
            ui.separator();
            ui.label(RichText::new("row").color(dim));
            ui.monospace(format!("{} / {}", self.top_row, self.total_view_rows()));
            if !self.folds.is_empty() {
                ui.separator();
                let label = format!("{} skipped", human_size(self.folds.hidden_bytes()));
                if ui.button(RichText::new(label).color(theme::FOLD)).on_hover_text("Bytes folded out of the views. Click to show them all again.").clicked() {
                    self.unfold_all();
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(format!("{:.2} ms", self.last_raster_ms)).color(dim))
                    .on_hover_text(format!("Last raster: {} pixels", self.last_raster_pixels));
                if let Some(range) = self.value_range {
                    ui.separator();
                    ui.monospace(format!("{} … {}", format_value(range.low), format_value(range.high)))
                        .on_hover_text("Heatmap range: the 1st to 99th percentile of the visible values (symmetric about zero for signed formats). NaN and infinities are magenta.");
                    ui.label(RichText::new("range").color(dim));
                }
                ui.separator();
                ui.label(RichText::new(&self.status).color(dim));
            });
        });
    }

    fn show_bookmark_prompt(&mut self, ctx: &Context) {
        let Some((offset, len, mut name)) = self.bookmark_prompt.clone() else { return };
        let mut keep_open = true;
        let mut commit = false;
        egui::Window::new("Bookmark")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(if len > 0 { format!("{len} bytes at {offset:#x}") } else { format!("Offset {offset:#x}") });
                let field = ui.add(egui::TextEdit::singleline(&mut name).desired_width(240.0).hint_text("name"));
                if !field.has_focus() && !field.lost_focus() {
                    field.request_focus();
                }
                // While the prompt is open, Enter always means Add.
                if ui.input(|i| i.key_pressed(Key::Enter)) {
                    commit = true;
                }
                ui.horizontal(|ui| {
                    if ui.button("Add").clicked() {
                        commit = true;
                    }
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                        keep_open = false;
                    }
                });
            });
        if commit {
            self.add_bookmark(offset, len, name);
            self.bookmark_prompt = None;
        } else if keep_open {
            self.bookmark_prompt = Some((offset, len, name));
        } else {
            self.bookmark_prompt = None;
        }
    }

    fn show_help_window(&mut self, ctx: &Context) {
        let mut open = self.show_help;
        egui::Window::new("Keyboard shortcuts")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                let rows: &[(&str, &str)] = &[
                    ("0–9 A–F", "Type hex: edit the byte at the cursor"),
                    ("Ins", "Toggle overwrite / insert mode"),
                    ("Arrow keys", "Move the cursor by a pixel / row (Shift to select)"),
                    ("PgUp PgDn Home End", "Move by a page / to the ends"),
                    ("Click, drag", "Place the cursor, select a range"),
                    ("Alt+drag", "Select a column: the same bytes in every record"),
                    ("Cmd+click  Cmd+drag", "Add a match, finding, packet or range to the selection (again to remove)"),
                    ("Drag a selection", "Move its bytes to the caret (Esc cancels); drag its first or last byte to resize"),
                    ("Alt+arrows", "With a selection: nudge its bytes a byte left or right, or a row up or down"),
                    ("I", "Insert bytes before, after or at the cursor"),
                    ("S", "Skip the selection: fold it out of the views (click the marker to show it)"),
                    ("M", "Multi-select mode: clicks and drags add sections; Esc clears and leaves"),
                    ("Backspace Del", "Delete the selection or byte"),
                    ("Cmd+Z Shift+Cmd+Z", "Undo, redo"),
                    ("Cmd+C Cmd+X Cmd+V Cmd+A", "Copy (as hex), cut, paste, select all"),
                    ("[ ]", "Width -1 / +1 (Shift: 16)"),
                    (", .", "Origin -1 / +1 byte"),
                    ("Alt+Left Alt+Right", "Origin -1 / +1 bit (when nothing is selected)"),
                    ("- +", "Zoom out / in (also Cmd+ + scroll, pinch)"),
                    ("Scroll", "Rows; Shift+scroll pans horizontally"),
                    ("Cmd+O Cmd+S Shift+Cmd+S Cmd+N", "Open, save, save as, new"),
                    ("Esc", "Clear the selection"),
                    ("Cmd+K", "Command palette: every action, searchable"),
                    ("Cmd+F  F3  Shift+F3", "Find bytes, text or a number; next and previous match"),
                    ("Cmd+G", "Go to offset"),
                    ("Cmd+B  F2  Shift+F2", "Bookmark the cursor or selection; next and previous bookmark"),
                    ("Right-click", "Actions for the byte or finding under the pointer"),
                    ("Cmd+Enter  Space", "Open the image, audio or video at the cursor; play and pause"),
                    ("Cmd+J  Cmd+L", "Tools dock; ask about the file"),
                    ("H", "Toggle pattern highlights"),
                    ("Cmd+D", "Open the compressed block at the cursor; back up a level where there is none"),
                    ("Cmd+E", "Extract the selection or stream to a file"),
                    ("Cmd+[", "Back to the parent document"),
                    ("?", "Toggle this window"),
                ];
                egui::Grid::new("help-grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                    for (keys, description) in rows {
                        theme::keycap(ui, keys);
                        ui.label(*description);
                        ui.end_row();
                    }
                });
            });
        self.show_help = open;
    }

    /// What to call the current document in the title and status bar.
    pub fn display_name(&self) -> String {
        self.derived_name.clone().unwrap_or_else(|| {
            self.document
                .path()
                .and_then(|path| path.file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "untitled".to_string())
        })
    }

    /// Only sends the viewport command when the title actually changes:
    /// re-sending it every frame makes macOS re-present the window.
    fn update_title(&mut self, ctx: &Context) {
        let name = self.display_name();
        let modified = if self.document.is_modified() { "*" } else { "" };
        let title = format!("{name}{modified} — theviewer");
        if title != self.last_title {
            ctx.send_viewport_cmd(ViewportCommand::Title(title.clone()));
            self.last_title = title;
        }
    }
}

impl eframe::App for ViewerApp {
    fn on_exit(&mut self) {
        self.save_sidecar();
        self.save_layout();
    }

    fn logic(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.handle_dropped_files(ctx);
        self.poll_file_request(ctx);
        self.poll_analysis(ctx);
        self.handle_shortcuts(ctx);
        self.perform_waiting_actions();
        self.folds.clamp_to(self.document.len());
        // After the shortcuts' edits and before anything that follows them.
        if self.run_bus() {
            ctx.request_repaint();
        }
        self.follow_edits(ctx);
        crate::panels::with(self, |panels| &mut panels.structure_map, crate::panel_structure_map::follow_document);
        self.poll_workbench(ctx);
        self.refresh_cursor_structure();
        self.update_title(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Whichever view the pointer is over sets this during the frame.
        self.hover = None;
        // The legend sets the layer to pick out while it is pointed at.
        self.emphasis = self.emphasis_next.take();
        egui::Panel::top("menu").show(ui, |ui| self.show_menu_bar(ui));
        egui::Panel::top("toolbar").show(ui, |ui| self.show_toolbar(ui));
        egui::Panel::bottom("status").show(ui, |ui| self.show_status_bar(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(theme::BACKGROUND))
            .show(ui, |ui| self.show_workspace(ui));
        if self.show_help {
            let ctx = ui.ctx().clone();
            self.show_help_window(&ctx);
        }
        let ctx = ui.ctx().clone();
        self.media.show(&ctx);
        self.show_plot_window(&ctx);
        self.show_settings_window(&ctx);
        self.show_confirmation_window(&ctx);
        self.show_recipe_window(&ctx);
        self.show_bookmark_prompt(&ctx);
        crate::selection_menu::show_insert_dialog(self, &ctx);
        commands::show_palette(self, &ctx);
        // When a panel starts or stops pointing at bytes, say so and draw
        // once more, so the views catch up without waiting for the pointer.
        if self.publish_pointed() {
            ctx.request_repaint();
        }
    }
}

/// A finding with a field tree, as `structure.identified` describes it.
pub fn structure_of(finding: &Finding) -> StructureIdentified {
    StructureIdentified { format: finding.id.clone(), title: finding.title.clone(), start: finding.start, len: finding.len, fields: finding.fields.clone() }
}

/// Human readable byte count, e.g. "1.2 MiB (1258291 B)".
pub fn human_size(bytes: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {} ({bytes} B)", UNITS[unit])
    }
}

/// An Edit menu item for undo or redo, naming the step when it was named:
/// "Undo XOR by mcp:claude-code   Cmd+Z".
pub fn history_item(verb: &str, label: Option<&str>, shortcut: &str) -> String {
    match label {
        Some(label) => format!("{verb} {label}   {shortcut}"),
        None => format!("{verb}   {shortcut}"),
    }
}

/// "name: error; name: error" for every report that failed, or empty.
fn failed_reports(reports: &[LoadReport]) -> String {
    reports
        .iter()
        .filter_map(|report| report.result.as_ref().err().map(|error| format!("{}: {error}", report.name)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// What a plugin action may do to the open document. Its edits go through
/// the data API, as the plugin's, so they are journalled.
impl ActionHost for ViewerApp {
    fn document_len(&self) -> usize {
        self.document.len()
    }

    fn cursor(&self) -> usize {
        self.cursor
    }

    fn selection(&self) -> Option<(usize, usize)> {
        ViewerApp::selection(self)
    }

    fn read(&mut self, start: usize, len: usize) -> Vec<u8> {
        self.document.read_range(start, len)
    }

    fn select(&mut self, start: usize, len: usize) {
        self.restore_selection(start.min(self.document.len()), len);
        self.reveal_cursor_in_hex(true);
    }

    fn set_status(&mut self, text: &str) {
        self.status = text.to_string();
    }

    fn workspace(&mut self) -> Option<&mut dyn crate::api::Workspace> {
        Some(self)
    }
}

/// A heatmap bound, short enough for the status bar.
fn format_value(value: f64) -> String {
    /// Magnitudes written in full; beyond them scientific notation is shorter.
    const PLAIN_LIMIT: f64 = 1.0e6;
    /// Magnitudes below this (other than zero) are written in scientific notation too.
    const SMALL_LIMIT: f64 = 1.0e-3;
    let magnitude = value.abs();
    if value == value.trunc() && magnitude < PLAIN_LIMIT {
        format!("{value:.0}")
    } else if magnitude >= PLAIN_LIMIT || magnitude < SMALL_LIMIT {
        format!("{value:.3e}")
    } else {
        format!("{value:.3}")
    }
}

/// `(start, len)` cut to a document of `document_len` bytes, or `None` when
/// nothing of it is left.
fn clip_range((start, len): (usize, usize), document_len: usize) -> Option<(usize, usize)> {
    let end = start.saturating_add(len).min(document_len);
    (end > start).then_some((start, end - start))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::actions::take_performed;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        take_performed();
        app
    }

    #[test]
    fn a_tool_named_at_launch_opens_and_an_unknown_one_is_reported() {
        let app = ViewerApp::new(Launch { tool: Some("Dot plot".to_string()), ..Default::default() });
        assert!(app.dock.open);
        assert_eq!(app.dock.tab, DockTab::DotPlot);
        let app = ViewerApp::new(Launch { tool: Some("sparkles".to_string()), ..Default::default() });
        assert!(!app.dock.open, "nothing is opened for it");
        assert_eq!(app.status, "No tool called 'sparkles'; theviewer --help lists them");
    }

    #[test]
    fn a_stream_inside_a_derived_document_is_followed_down_and_cmd_d_goes_back_where_none_is() {
        let mut app = app_with(b"outer");
        let bytes = crate::api::test_support::example_bytes();
        let stream_len = bytes.iter().position(|&byte| byte == b'T').unwrap();
        app.open_derived(bytes, "reassembled".to_string());
        // As the background scan finds it.
        app.patterns = vec![Finding::new("compressed-streams", "builtin", Category::Compressed, 0, stream_len).title("zlib stream")];
        app.toggle_compressed_view();
        assert_eq!(app.parents.len(), 2, "the stream at the cursor is opened, one level deeper: {}", app.status);
        assert_eq!(app.document.read_range(0, 6), b"hello ");
        app.toggle_compressed_view();
        assert_eq!(app.parents.len(), 1, "no stream at the cursor, so back up a level");
    }

    #[test]
    fn a_decompressed_child_names_the_file_it_came_from() {
        let path = std::env::temp_dir().join(format!("theviewer-parent-name-{}.bin", std::process::id()));
        std::fs::write(&path, b"outer bytes").unwrap();
        let mut app = ViewerApp::new(Launch::default());
        app.open_file(&path);
        app.open_derived(b"inner".to_vec(), "zlib@0x0".to_string());
        let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(app.parents.last().map(|parent| parent.name.as_str()), Some(file_name.as_str()));
        app.go_back_to_parent();
        assert_eq!(app.status, format!("Back to {file_name}"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn going_to_an_offset_moves_the_cursor_through_the_api() {
        let mut app = app_with(&[0u8; 256]);
        let cursor = app.bus.cursor();
        app.goto_text = "0x40".to_string();
        app.go_to();
        assert_eq!(take_performed(), [("cursor.set".to_string(), json!({"offset": 0x40}))]);
        assert_eq!((app.cursor, app.status.as_str()), (0x40, "Cursor at 0x40"));
        app.run_bus();
        let moved = app.bus.changed_since(cursor).messages.into_iter().find(|message| message.topic() == crate::bus::Topic::CursorMoved).expect("the move is published");
        assert_eq!(moved.producer(), "panel");
    }

    #[test]
    fn going_past_the_end_goes_to_the_end_and_a_bad_offset_changes_nothing() {
        let mut app = app_with(&[0u8; 16]);
        app.goto_text = "1000".to_string();
        app.go_to();
        assert_eq!(app.cursor, 16);
        app.goto_text = "somewhere".to_string();
        app.go_to();
        assert_eq!(app.cursor, 16);
        assert!(app.status.starts_with("Go to:"), "{}", app.status);
        assert_eq!(take_performed().len(), 1, "only the offset that parsed was performed");
    }

    #[test]
    fn detecting_the_width_from_the_palette_is_a_period_scan_job_that_fills_the_chart() {
        let records: Vec<u8> = (0..400u32)
            .flat_map(|index| {
                let mut record = vec![0xA5, 0x5A, index as u8, (index >> 8) as u8];
                record.extend((0..44u8).map(|byte| byte.wrapping_mul(7)));
                record
            })
            .collect();
        let mut app = app_with(&records);
        app.set_width(64);
        app.shape.byte_offset = 0;
        let detect = crate::commands::commands().into_iter().find(|command| command.id == "analysis.detect").unwrap();
        let ctx = Context::default();
        (detect.run)(&mut app, &ctx);
        let performed = take_performed();
        assert_eq!(performed.len(), 1);
        assert_eq!(performed[0].0, "analysis.period_scan");
        assert_eq!(performed[0].1, json!({"start": 0, "len": SCAN_WINDOW, "max_period": app.scan_max_period}), "the window and the longest period are in the step");
        let begun = std::time::Instant::now();
        while app.period_scan.is_none() && begun.elapsed() < std::time::Duration::from_secs(20) {
            app.poll_analysis(&ctx);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(app.period_scan.as_ref().and_then(|scan| scan.candidates.first()).map(|best| best.period), Some(48));
        app.run_bus();
        let job = app.bus.jobs().list().into_iter().find(|job| job.title == "Period scan").expect("the scan is a job");
        assert_eq!(job.producer, "panel", "the person started it");
    }

    #[test]
    fn the_person_s_width_changes_are_view_shape_steps_the_api_reports() {
        let mut app = app_with(&[0u8; 1024]);
        app.change_width(48);
        app.change_width(MAX_WIDTH + 10);
        assert_eq!(take_performed(), [("view.set_shape".to_string(), json!({"width": 48})), ("view.set_shape".to_string(), json!({"width": MAX_WIDTH}))]);
        assert_eq!(app.shape.width, MAX_WIDTH, "a width past the limit is brought inside it");
        let shape = crate::api::call(&mut app, &crate::api::Caller::Panel, "view.get_shape", json!({})).unwrap();
        assert_eq!(shape["shape"]["width"], MAX_WIDTH);
    }

    #[test]
    fn selecting_the_stream_at_the_cursor_is_the_person_s_selection_through_the_api() {
        let mut app = app_with(&[0u8; 256]);
        app.patterns = vec![Finding::new("gzip", "test", Category::Compressed, 0x20, 0x30).title("gzip stream")];
        app.select_stream_at_cursor();
        assert_eq!(take_performed(), [], "the cursor is not inside the stream");
        assert_eq!(app.status, "The cursor is not inside a recognised compressed stream");

        app.cursor = 0x28;
        app.select_stream_at_cursor();
        assert_eq!(take_performed(), [("selection.set".to_string(), json!({ "selection": { "range": [0x20, 0x30] } }))]);
        assert_eq!((app.selection(), app.cursor), (Some((0x20, 0x30)), 0x50));
        assert!(app.status.contains("gzip stream"), "the status bar names the stream: {}", app.status);
    }
}
