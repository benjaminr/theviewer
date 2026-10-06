//! The command palette: every action the app can do, searchable by name,
//! with its shortcut shown. Plugins add their actions to the same list.

use eframe::egui::{self, Align2, Context, Key, RichText};

use crate::app::ViewerApp;
use crate::compress::Codec;
use crate::theme;

/// One thing the user can ask for.
pub struct Command {
    pub id: &'static str,
    pub title: &'static str,
    /// Human readable shortcut, empty when there is none.
    pub keys: &'static str,
    pub run: fn(&mut ViewerApp, &Context),
}

/// Every built-in command. Scripted actions are appended by the palette.
pub fn commands() -> Vec<Command> {
    vec![
        Command { id: "file.open", title: "Open file", keys: "Cmd+O", run: |app, _| app.open_dialog() },
        Command { id: "file.save", title: "Save", keys: "Cmd+S", run: |app, _| app.save() },
        Command { id: "file.save_as", title: "Save as", keys: "Shift+Cmd+S", run: |app, _| app.save_as_dialog() },
        Command { id: "file.new", title: "New empty document", keys: "Cmd+N", run: |app, _| app.new_document() },
        Command { id: "file.extract", title: "Extract selection or stream to file", keys: "Cmd+E", run: |app, _| app.export_dialog(false) },
        Command { id: "file.extract_decompressed", title: "Extract decompressed contents to file", keys: "", run: |app, _| app.export_dialog(true) },
        Command { id: "edit.undo", title: "Undo", keys: "Cmd+Z", run: |app, _| app.undo() },
        Command { id: "edit.redo", title: "Redo", keys: "Shift+Cmd+Z", run: |app, _| app.redo() },
        Command { id: "edit.copy", title: "Copy as hex", keys: "Cmd+C", run: |app, ctx| app.copy(ctx) },
        Command { id: "edit.cut", title: "Cut", keys: "Cmd+X", run: |app, ctx| app.cut(ctx) },
        Command { id: "edit.paste", title: "Paste", keys: "Cmd+V", run: |app, _| app.paste(None) },
        Command { id: "edit.select_all", title: "Select all", keys: "Cmd+A", run: |app, _| app.select_all() },
        Command { id: "edit.delete", title: "Delete selection or byte", keys: "Del", run: |app, _| app.delete_target() },
        Command { id: "edit.insert", title: "Insert bytes at cursor", keys: "", run: |app, _| app.insert_from_fields() },
        Command { id: "edit.fill", title: "Fill selection with pattern", keys: "", run: |app, _| app.fill_target() },
        Command { id: "edit.invert", title: "Invert bits in selection", keys: "", run: |app, _| app.invert_target() },
        Command { id: "edit.reverse", title: "Reverse bytes in selection", keys: "", run: |app, _| app.reverse_target() },
        Command { id: "edit.mirror", title: "Mirror bits in each selected byte", keys: "", run: |app, _| app.mirror_target() },
        Command { id: "edit.mode", title: "Toggle overwrite / insert typing", keys: "Ins", run: |app, _| app.toggle_edit_mode() },
        Command { id: "view.zoom_in", title: "Zoom in", keys: "+", run: |app, _| app.zoom_step(1) },
        Command { id: "view.zoom_out", title: "Zoom out", keys: "-", run: |app, _| app.zoom_step(-1) },
        Command { id: "view.fit", title: "Fit width to the window", keys: "", run: |app, _| app.fit_width_requested = true },
        Command { id: "view.origin_cursor", title: "Set view origin to the cursor", keys: "", run: |app, _| app.align_view_to_cursor() },
        Command { id: "view.origin_reset", title: "Reset view origin to 0", keys: "", run: |app, _| app.reset_origin() },
        Command { id: "view.goto", title: "Go to offset", keys: "Cmd+G", run: |app, _| app.focus_goto = true },
        Command { id: "view.search", title: "Find bytes or text", keys: "Cmd+F", run: |app, _| app.focus_search = true },
        Command { id: "view.find_next", title: "Find next", keys: "F3", run: |app, _| app.find_next() },
        Command { id: "view.find_previous", title: "Find previous", keys: "Shift+F3", run: |app, _| app.find_previous() },
        Command { id: "view.guess_image", title: "Guess image shape", keys: "", run: |app, _| app.guess_image_shape() },
        Command { id: "analysis.detect", title: "Detect width (period scan)", keys: "", run: |app, _| app.start_period_scan() },
        Command { id: "analysis.chart", title: "Toggle structure chart", keys: "", run: |app, _| app.toggle_panel(crate::layout::Pane::PeriodChart) },
        Command { id: "analysis.patterns", title: "Toggle highlights", keys: "H", run: |app, _| app.highlight_patterns = !app.highlight_patterns },
        Command { id: "analysis.findings", title: "Toggle findings panel", keys: "", run: |app, _| app.pattern_list_open = !app.pattern_list_open },
        Command { id: "analysis.rescan", title: "Rescan the visible region", keys: "", run: |app, _| app.force_rescan() },
        Command { id: "compress.flip", title: "Flip compressed / decompressed view", keys: "Cmd+D", run: |app, _| app.toggle_compressed_view() },
        Command { id: "compress.in_place", title: "Decompress in place", keys: "", run: |app, _| app.decompress_in_place() },
        Command { id: "compress.probe", title: "Probe for compression at cursor", keys: "", run: |app, _| app.probe_at_cursor() },
        Command { id: "compress.select_stream", title: "Select the stream at the cursor", keys: "", run: |app, _| app.select_stream_at_cursor() },
        Command { id: "compress.repack", title: "Re-pack selection with the last codec", keys: "", run: |app, _| app.recompress_selection() },
        Command { id: "compress.zlib", title: "Compress selection as zlib", keys: "", run: |app, _| app.compress_selection(Codec::Zlib) },
        Command { id: "compress.gzip", title: "Compress selection as gzip", keys: "", run: |app, _| app.compress_selection(Codec::Gzip) },
        Command { id: "compress.bzip2", title: "Compress selection as bzip2", keys: "", run: |app, _| app.compress_selection(Codec::Bzip2) },
        Command { id: "compress.lz4", title: "Compress selection as LZ4", keys: "", run: |app, _| app.compress_selection(Codec::Lz4) },
        Command { id: "compress.back", title: "Back to the parent document", keys: "Cmd+[", run: |app, _| app.back_to_parent() },
        Command { id: "bookmark.add", title: "Bookmark the cursor or selection", keys: "Cmd+B", run: |app, _| app.begin_bookmark() },
        Command { id: "bookmark.next", title: "Next bookmark", keys: "F2", run: |app, _| app.goto_bookmark(true) },
        Command { id: "bookmark.previous", title: "Previous bookmark", keys: "Shift+F2", run: |app, _| app.goto_bookmark(false) },
        Command { id: "plugins.reload", title: "Reload plugins", keys: "", run: |app, _| app.reload_plugins() },
        Command { id: "media.open", title: "View image / play audio or video at the cursor", keys: "Cmd+Enter", run: |app, _| app.open_media() },
        Command { id: "media.toggle", title: "Play or pause media", keys: "Space", run: |app, _| app.media.toggle_play() },
        Command { id: "media.close", title: "Close the media window", keys: "", run: |app, _| app.media.close() },
        Command { id: "tools.explain", title: "Explain this file (report and file map)", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Report; app.start_report(); } },
        Command { id: "tools.ask", title: "Ask Claude about this file", keys: "Cmd+L", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Assistant; } },
        Command { id: "tools.ask_characterise", title: "Characterise this file with Ask", keys: "", run: |app, _| app.characterise_with_ask() },
        Command { id: "tools.template", title: "Templates", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Template) },
        Command { id: "tools.infer", title: "Infer a template from the selection", keys: "", run: |app, _| app.infer_template() },
        Command { id: "tools.disassemble", title: "Disassemble at the cursor", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Disassembly; } },
        Command { id: "tools.unpack", title: "Unpack everything (recursive extraction)", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Unpacked; app.start_unpack(); } },
        Command { id: "tools.segments", title: "Segment the file into regions of one kind", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::StructureMap) },
        Command { id: "tools.similar", title: "Find more like the selection", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::StructureMap) },
        Command { id: "tools.trigrams", title: "Trigram cube: a 3D fingerprint of the bytes", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Trigrams) },
        Command { id: "tools.sizemap", title: "Size map of regions or unpacked contents", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::SizeMap) },
        Command { id: "tools.dotplot", title: "Dot plot: compare the file with itself", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::DotPlot) },
        Command { id: "tools.images", title: "Find uncompressed images, fonts and framebuffers", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Images) },
        Command { id: "tools.firmware", title: "Firmware: identify the processor, load address and vector table", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Firmware) },
        Command { id: "tools.crc_solver", title: "Solve a custom CRC from several messages", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Checksums) },
        Command { id: "tools.forensics", title: "Find embedded filesystems and classify each block of the file", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Forensics) },
        Command { id: "tools.checksums", title: "Checksums and find-the-checksum", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Checksums) },
        Command { id: "tools.diff", title: "Compare with another file", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Diff; } },
        Command { id: "tools.live", title: "Open a URL, device, serial port or process", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Live; } },
        Command { id: "tools.watch", title: "Watch the file for changes", keys: "", run: |app, _| { let on = !app.bench.watch_enabled; app.set_watch(on); } },
        Command { id: "tools.plot", title: "Plot the selection", keys: "", run: |app, _| app.open_plot() },
        Command { id: "tools.audio", title: "Play the selection as audio", keys: "", run: |app, _| app.play_bytes_as_audio() },
        Command { id: "view.dock", title: "Toggle the tools dock", keys: "Cmd+J", run: |app, _| app.dock.open = !app.dock.open },
        Command { id: "view.hilbert", title: "Toggle Hilbert-curve layout", keys: "", run: |app, _| app.bench.toggle_layout(crate::workbench::Layout::Hilbert) },
        Command { id: "view.morton", title: "Toggle Morton (Z-order) curve layout", keys: "", run: |app, _| app.bench.toggle_layout(crate::workbench::Layout::Morton) },
        Command { id: "view.curve_colours", title: "Cycle curve colours: bytes, entropy, region type, byte class", keys: "", run: |app, _| app.bench.curve_colour = app.bench.curve_colour.next() },
        Command { id: "view.pixel_values", title: "Toggle values inside pixels when zoomed in", keys: "", run: |app, _| app.show_pixel_values = !app.show_pixel_values },
        Command { id: "view.zoomed_out_regions", title: "Toggle colouring by region when zoomed out", keys: "", run: |app, _| app.colour_regions_when_zoomed_out = !app.colour_regions_when_zoomed_out },
        Command { id: "view.row_difference", title: "Cycle row difference: off, XOR or subtract the row above", keys: "", run: |app, _| app.cycle_row_difference() },
        Command { id: "view.pointers", title: "Toggle pointer arrows", keys: "", run: |app, _| app.bench.analysis.show_pointers = !app.bench.analysis.show_pointers },
        Command { id: "tools.characterise", title: "Characterise: compressibility by codec, raw media streams, text encoding", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Characterise) },
        Command { id: "tools.learn", title: "Learn a format from samples; fuzzy-match files", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Learn) },
        Command { id: "tools.statistics", title: "Byte statistics and randomness tests", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Statistics; crate::analysis_stats::start_statistics(app); } },
        Command { id: "tools.strings", title: "Find strings", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Strings; } },
        Command { id: "tools.bits", title: "Bits and encodings: bit periods, bit planes, line codes, number types, length fields", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Bits) },
        Command { id: "tools.columns", title: "Profile record columns", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Columns; } },
        Command { id: "tools.protocol", title: "Analyse a message stream (protocol)", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Protocol; crate::analysis_tools::start_protocol(app); } },
        Command { id: "tools.packets", title: "Packet viewer: dissect, filter and export packets", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Packets) },
        Command { id: "tools.packets_framing", title: "Packets from the protocol framing", keys: "", run: |app, _| crate::panel_packets::open_protocol_messages(app) },
        Command { id: "tools.packets_selection", title: "Add the selection as a packet", keys: "", run: |app, _| crate::panel_packets::add_selection_as_packet(app) },
        Command { id: "tools.packets_rows", title: "Split the selection into packets by row width", keys: "", run: |app, _| crate::panel_packets::split_selection_by_row_width(app) },
        Command { id: "tools.xor", title: "Recover XOR keys", keys: "", run: |app, _| { app.dock.open = true; app.dock.tab = crate::dock::DockTab::Xor; } },
        Command { id: "tools.compare", title: "Compare many files: variation, correlation and recording timeline", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Compare) },
        Command { id: "tools.crypto", title: "Find encrypted blocks, keys and certificates; try simple ciphers", keys: "", run: |app, _| app.dock.toggle(crate::dock::DockTab::Crypto) },
        Command { id: "app.settings", title: "Settings (API key)", keys: "Cmd+,", run: |app, _| app.open_settings() },
        Command { id: "help.keys", title: "Keyboard shortcuts", keys: "?", run: |app, _| app.show_help = true },
    ]
}

/// Palette state kept by the app.
#[derive(Default)]
pub struct PaletteState {
    pub open: bool,
    pub query: String,
    pub selected: usize,
    needs_focus: bool,
}

impl PaletteState {
    pub fn toggle(&mut self) {
        self.open = !self.open;
        if self.open {
            self.query.clear();
            self.selected = 0;
            self.needs_focus = true;
        }
    }
}

/// Case-insensitive match of every query word somewhere in the title or id.
fn matches(query: &str, title: &str, id: &str) -> bool {
    let haystack = format!("{} {}", title.to_lowercase(), id.to_lowercase());
    query.split_whitespace().all(|word| haystack.contains(&word.to_lowercase()))
}

/// Draw the palette and run the chosen command.
pub fn show_palette(app: &mut ViewerApp, ctx: &Context) {
    if !app.palette.open {
        return;
    }
    let builtin = commands();
    let scripted = app.plugin_actions();
    let query = app.palette.query.clone();
    let mut visible: Vec<(usize, bool)> = Vec::new(); // (index, is_scripted)
    for (index, command) in builtin.iter().enumerate() {
        if matches(&query, command.title, command.id) {
            visible.push((index, false));
        }
    }
    for (index, action) in scripted.iter().enumerate() {
        if matches(&query, &action.title, &action.id) {
            visible.push((index, true));
        }
    }
    if app.palette.selected >= visible.len() {
        app.palette.selected = visible.len().saturating_sub(1);
    }

    let (escape, enter, down, up) = ctx.input_mut(|i| {
        (
            i.consume_key(egui::Modifiers::NONE, Key::Escape),
            i.consume_key(egui::Modifiers::NONE, Key::Enter),
            i.consume_key(egui::Modifiers::NONE, Key::ArrowDown),
            i.consume_key(egui::Modifiers::NONE, Key::ArrowUp),
        )
    });
    if escape {
        app.palette.open = false;
        return;
    }
    if down && !visible.is_empty() {
        app.palette.selected = (app.palette.selected + 1) % visible.len();
    }
    if up && !visible.is_empty() {
        app.palette.selected = (app.palette.selected + visible.len() - 1) % visible.len();
    }

    let mut chosen: Option<(usize, bool)> = None;
    egui::Window::new("Command palette")
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .fixed_size([560.0, 420.0])
        .anchor(Align2::CENTER_TOP, [0.0, 80.0])
        .show(ctx, |ui| {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut app.palette.query)
                    .hint_text("Type a command…  (↑ ↓ to choose, Enter to run, Esc to close)")
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Heading),
            );
            if app.palette.needs_focus {
                edit.request_focus();
                app.palette.needs_focus = false;
            }
            if edit.changed() {
                app.palette.selected = 0;
            }
            ui.separator();
            egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
                for (row, &(index, scripted_row)) in visible.iter().enumerate() {
                    let (title, keys, id) = if scripted_row {
                        (scripted[index].title.clone(), "plugin".to_string(), scripted[index].id.clone())
                    } else {
                        (builtin[index].title.to_string(), builtin[index].keys.to_string(), builtin[index].id.to_string())
                    };
                    let selected = row == app.palette.selected;
                    let response = ui.horizontal(|ui| {
                        let label = ui.selectable_label(selected, RichText::new(&title).size(15.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if !keys.is_empty() {
                                theme::keycap(ui, &keys);
                            }
                            ui.label(RichText::new(id).small().color(theme::TEXT_DIM));
                        });
                        label
                    });
                    if response.inner.clicked() {
                        chosen = Some((index, scripted_row));
                    }
                    if selected {
                        response.inner.scroll_to_me(None);
                    }
                }
                if visible.is_empty() {
                    ui.label(RichText::new("No matching command").color(theme::TEXT_DIM));
                }
            });
        });

    if enter && chosen.is_none() {
        chosen = visible.get(app.palette.selected).copied();
    }
    if let Some((index, scripted_row)) = chosen {
        app.palette.open = false;
        if scripted_row {
            let id = scripted[index].id.clone();
            app.run_plugin_action(&id);
        } else {
            (builtin[index].run)(app, ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_words_match_anywhere_in_title_or_id() {
        assert!(matches("zoom in", "Zoom in", "view.zoom_in"));
        assert!(matches("IN zoom", "Zoom in", "view.zoom_in"));
        assert!(matches("compress.gz", "Compress selection as gzip", "compress.gzip"));
        assert!(!matches("zoom out", "Zoom in", "view.zoom_in"));
        assert!(matches("", "anything", "x"));
    }

    #[test]
    fn command_ids_are_unique() {
        let all = commands();
        let mut ids: Vec<&str> = all.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), all.len());
    }
}
