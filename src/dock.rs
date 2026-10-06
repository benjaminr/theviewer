//! The dock: a tabbed panel under the raster for the analysis tools that need
//! more room than the toolbar - the report, the assistant, templates,
//! disassembly, unpacking, checksums, diff and live sources.
//!
//! Each tab is a function taking the app; state that only matters to one tab
//! lives in `DockState`.

use eframe::egui::{self, RichText, Sense, Ui, vec2};

use crate::app::ViewerApp;
use crate::assistant::{self, Segment, Turn};
use crate::theme;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DockTab {
    Report,
    Assistant,
    Template,
    Columns,
    Protocol,
    Statistics,
    Strings,
    Xor,
    Checksums,
    Disassembly,
    Unpacked,
    Diff,
    Live,
    Crypto,
    Compare,
    Bits,
    Forensics,
    DotPlot,
    Images,
    Firmware,
    StructureMap,
    Trigrams,
    SizeMap,
    Characterise,
    Learn,
}

impl DockTab {
    pub const ALL: [DockTab; 25] = [
        DockTab::Report,
        DockTab::Assistant,
        DockTab::Template,
        DockTab::Columns,
        DockTab::Protocol,
        DockTab::Statistics,
        DockTab::Strings,
        DockTab::Xor,
        DockTab::Checksums,
        DockTab::Disassembly,
        DockTab::Unpacked,
        DockTab::Diff,
        DockTab::Live,
        DockTab::Crypto,
        DockTab::Compare,
        DockTab::Bits,
        DockTab::Forensics,
        DockTab::DotPlot,
        DockTab::Images,
        DockTab::Firmware,
        DockTab::StructureMap,
        DockTab::Trigrams,
        DockTab::SizeMap,
        DockTab::Characterise,
        DockTab::Learn,
    ];

    /// Tabs grouped by purpose, for the tab bar.
    pub const GROUPS: [&'static [DockTab]; 5] = [
        &[DockTab::Report, DockTab::StructureMap, DockTab::SizeMap, DockTab::Assistant, DockTab::DotPlot, DockTab::Trigrams, DockTab::Images],
        &[DockTab::Template, DockTab::Columns, DockTab::Protocol, DockTab::Bits],
        &[DockTab::Statistics, DockTab::Characterise, DockTab::Strings, DockTab::Xor, DockTab::Crypto, DockTab::Checksums, DockTab::Learn],
        &[DockTab::Disassembly, DockTab::Firmware, DockTab::Unpacked, DockTab::Forensics, DockTab::Diff, DockTab::Compare],
        &[DockTab::Live],
    ];

    pub fn label(self) -> &'static str {
        match self {
            DockTab::Report => "Report",
            DockTab::Assistant => "Ask",
            DockTab::Template => "Template",
            DockTab::Columns => "Columns",
            DockTab::Protocol => "Protocol",
            DockTab::Statistics => "Statistics",
            DockTab::Strings => "Strings",
            DockTab::Xor => "XOR",
            DockTab::Checksums => "Checksums",
            DockTab::Disassembly => "Disassembly",
            DockTab::Unpacked => "Unpacked",
            DockTab::Diff => "Diff",
            DockTab::Live => "Live",
            DockTab::Crypto => "Crypto",
            DockTab::Compare => "Compare",
            DockTab::Bits => "Bits",
            DockTab::Forensics => "Forensics",
            DockTab::DotPlot => "Dot plot",
            DockTab::Images => "Images",
            DockTab::Firmware => "Firmware",
            DockTab::StructureMap => "Structure map",
            DockTab::Trigrams => "Trigrams",
            DockTab::SizeMap => "Size map",
            DockTab::Characterise => "Characterise",
            DockTab::Learn => "Learn",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            DockTab::Report => "What the whole file is, part by part",
            DockTab::Assistant => "Ask Claude about the file",
            DockTab::Template => "Describe a structure and decode it",
            DockTab::Columns => "Which byte positions of each record are fields",
            DockTab::Protocol => "Framing and header fields of a message stream",
            DockTab::Statistics => "Byte histogram, randomness tests, entropy and repeats",
            DockTab::Strings => "Text in the data",
            DockTab::Xor => "Recover XOR keys",
            DockTab::Checksums => "Digests and stored checksums",
            DockTab::Disassembly => "Machine code",
            DockTab::Unpacked => "Nested archives and streams",
            DockTab::Diff => "Compare with another file",
            DockTab::Live => "URLs, devices, serial, watch and history",
            DockTab::Crypto => "Encrypted blocks, keys and certificates, and simple ciphers",
            DockTab::Compare => "Many files: what varies, what follows an outside value, and a recording's timeline",
            DockTab::Bits => "Bit-level frames, bit planes, line codes, number types and length fields",
            DockTab::Forensics => "Embedded filesystems, and what kind of data each block holds",
            DockTab::DotPlot => "The file compared with itself: repeats show as diagonal lines",
            DockTab::Images => "Find uncompressed pictures, fonts and framebuffers",
            DockTab::Firmware => "Processor, load address and vector table of a raw firmware image",
            DockTab::StructureMap => "Split the file into regions of one kind, find more like the selection, and track features along the file",
            DockTab::Trigrams => "A rotatable 3D cloud of byte triples: a fingerprint of text, code, tables and compressed data",
            DockTab::SizeMap => "What takes up the space: regions or unpacked contents as nested rectangles",
            DockTab::Characterise => "Compressibility by codec, raw audio and video streams, and text encoding and language",
            DockTab::Learn => "Learn a new format from samples, and fuzzy-match files and shared fragments",
        }
    }
}

/// Per-tab state that is not part of the document.
pub struct DockState {
    /// Asks for the tools to be visible; set by menus, palette and links.
    pub open: bool,
    /// The tool most recently asked for (or drawn).
    pub tab: DockTab,
    /// The tool the layout last brought forward, so a new request is noticed.
    pub shown: Option<DockTab>,
    pub question: String,
    pub source_text: String,
    /// Set when a link in a tab asks to jump somewhere.
    pub jump_to: Option<usize>,
    /// Set when the assistant offers a template and the user applies it.
    pub apply_template: Option<String>,
}

impl Default for DockState {
    fn default() -> Self {
        DockState {
            open: false,
            tab: DockTab::Report,
            shown: None,
            question: String::new(),
            source_text: String::new(),
            jump_to: None,
            apply_template: None,
        }
    }
}

impl DockState {
    /// Bring a tool forward, adding its pane back if it was closed.
    pub fn toggle(&mut self, tab: DockTab) {
        self.open = true;
        self.tab = tab;
        self.shown = None;
    }
}

/// Draw one tool's pane.
pub fn show_tool(app: &mut ViewerApp, ui: &mut Ui, tool: DockTab) {
    match tool {
        DockTab::Assistant => show_assistant(app, ui),
        DockTab::Live => show_live(app, ui),
        other => app.show_dock_tab(other, ui),
    }
    if let Some(offset) = app.dock.jump_to.take() {
        app.jump_to_offset(offset);
    }
    if let Some(source) = app.dock.apply_template.take() {
        app.apply_template_source(&source);
    }
}

/// Text with clickable `0x…` offsets.
pub fn linked_text(app: &mut ViewerApp, ui: &mut Ui, text: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for segment in assistant::segments(text) {
            match segment {
                Segment::Text(plain) => {
                    ui.label(plain);
                }
                Segment::Offset(offset, label) => {
                    let link = ui.add(egui::Label::new(RichText::new(label).color(theme::ACCENT).underline()).sense(Sense::click()));
                    if link.on_hover_text("Jump here").clicked() {
                        app.dock.jump_to = Some(offset);
                    }
                }
                Segment::Template(source) => {
                    ui.end_row();
                    template_offer(app, ui, &source);
                    ui.end_row();
                }
            }
        }
    });
}

fn template_offer(app: &mut ViewerApp, ui: &mut Ui, source: &str) {
    egui::Frame::new()
        .fill(theme::SURFACE)
        .stroke(egui::Stroke::new(1.0, theme::OUTLINE))
        .corner_radius(6)
        .inner_margin(8)
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Template").strong());
                    if ui.button("Apply at cursor").clicked() {
                        app.dock.apply_template = Some(source.to_string());
                    }
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(source.to_string());
                    }
                });
                ui.label(RichText::new(source).monospace().small());
            });
        });
}

// ---------------------------------------------------------------------------
// Ask the file
// ---------------------------------------------------------------------------

const SUGGESTIONS: [&str; 4] = [
    "What is this file, and what are its main parts?",
    "What is at the cursor?",
    "Write a template for the records around the cursor.",
    "Is anything here compressed, encrypted or checksummed?",
];

/// Shown in place of the assistant when there is no key.
fn show_assistant_setup(app: &mut ViewerApp, ui: &mut Ui) {
    ui.add_space(12.0);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new("Ask Claude about this file").heading());
        ui.label(
            RichText::new("Ask needs an Anthropic API key. It sends your question, a snapshot around the cursor, and the bytes it chooses to read. Nothing is sent until you ask.")
                .color(theme::TEXT_DIM),
        );
        ui.add_space(8.0);
        if ui.add(egui::Button::new(RichText::new("Add API key…").strong()).min_size(vec2(160.0, 28.0))).clicked() {
            app.open_settings();
        }
        ui.add_space(4.0);
        ui.label(RichText::new("or set ANTHROPIC_API_KEY before launching").small().color(theme::TEXT_DIM));
    });
    ui.add_space(8.0);
    ui.add_enabled_ui(false, |ui| {
        ui.horizontal(|ui| {
            let mut placeholder = String::new();
            ui.add(egui::TextEdit::singleline(&mut placeholder).hint_text("Ask about the file…").desired_width((ui.available_width() - 80.0).max(100.0)));
            let _ = ui.button("Ask");
        });
    });
}

fn show_assistant(app: &mut ViewerApp, ui: &mut Ui) {
    if !app.assistant_available() {
        show_assistant_setup(app, ui);
        return;
    }
    let available = ui.available_height();
    egui::ScrollArea::vertical()
        .id_salt("assistant-transcript")
        .max_height((available - 70.0).max(60.0))
        .stick_to_bottom(true)
        .show(ui, |ui| {
            if app.assistant.transcript.is_empty() {
                ui.label(RichText::new(format!(
                    "Ask {} about this file. It sees the cursor, selection, findings and nearby bytes, and can read, search and parse the file itself.",
                    assistant::MODEL
                ))
                .color(theme::TEXT_DIM));
                ui.horizontal_wrapped(|ui| {
                    for suggestion in SUGGESTIONS {
                        if ui.button(suggestion).clicked() {
                            app.dock.question = suggestion.to_string();
                            app.ask_assistant();
                        }
                    }
                });
            }
            for turn in app.assistant.transcript.clone() {
                match turn {
                    Turn::User(text) => {
                        ui.add_space(6.0);
                        ui.label(RichText::new(text).strong().color(theme::CURSOR));
                    }
                    Turn::Assistant(text) => linked_text(app, ui, &text),
                    Turn::Reasoning(text) => {
                        egui::CollapsingHeader::new(RichText::new("Reasoning").small().color(theme::TEXT_DIM))
                            .id_salt(text.len() ^ text.as_ptr() as usize)
                            .show(ui, |ui| {
                                ui.label(RichText::new(text).small().color(theme::TEXT_DIM));
                            });
                    }
                    Turn::Tool(text) => {
                        ui.label(RichText::new(format!("· {text}")).small().monospace().color(theme::TEXT_DIM));
                    }
                    Turn::Note(text) => {
                        ui.label(RichText::new(text).color(theme::DANGER));
                    }
                }
            }
            if app.assistant.is_busy() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Thinking…").color(theme::TEXT_DIM));
                });
            }
        });
    ui.separator();
    ui.horizontal(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(&mut app.dock.question)
                .hint_text("Ask about the file…  (Enter to send)")
                .desired_width((ui.available_width() - 260.0).max(100.0)),
        );
        let send = ui.add_enabled(!app.assistant.is_busy(), egui::Button::new("Ask"));
        if send.clicked() || (field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
            app.ask_assistant();
            field.request_focus();
        }
        if ui.add_enabled(!app.assistant.is_busy(), egui::Button::new("Clear")).clicked() {
            app.assistant.clear();
        }
        if ui
            .add_enabled(!app.assistant.is_busy(), egui::Button::new("Characterise"))
            .on_hover_text("Have Claude run the analysis tools and describe what this file is, part by part")
            .clicked()
        {
            app.characterise_with_ask();
        }
    });
}

// ---------------------------------------------------------------------------
// Live sources, watch mode and recording
// ---------------------------------------------------------------------------

fn show_live(app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label("Open");
        let field = ui.add(
            egui::TextEdit::singleline(&mut app.dock.source_text)
                .hint_text("https://…  ·  serial:/dev/cu.usbserial@115200  ·  /dev/rdisk2  ·  pid:1234")
                .desired_width(420.0),
        );
        if ui.button("Open").clicked() || (field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
            let text = app.dock.source_text.clone();
            app.open_source(&text);
        }
        if app.source_loading() {
            ui.spinner();
        }
    });
    let ports = crate::sources::list_serial_ports();
    if !ports.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Serial ports:").small().color(theme::TEXT_DIM));
            for port in ports {
                if ui.small_button(&port).clicked() {
                    app.dock.source_text = format!("serial:{port}@{}", crate::sources::DEFAULT_BAUD);
                }
            }
        });
    }
    ui.separator();
    app.show_live_status(ui);
    ui.add_space(4.0);
    app.show_recording(ui);
}

/// A thin bar that fills the width, used for timelines and maps.
pub fn timeline_bar(ui: &mut Ui, height: f32) -> (egui::Rect, egui::Response) {
    ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click_and_drag())
}
