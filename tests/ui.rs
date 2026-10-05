//! Headless UI tests: drive the real application through egui_kittest and
//! make sure clicking, typing and extreme settings never panic and do what
//! they say.

use std::path::PathBuf;

use eframe::egui::{self, Event, Key, Modifiers, PointerButton, pos2};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use theviewer::app::{EditMode, Launch, ViewerApp};
use theviewer::raster::{Palette, PixelFormat};

const SAMPLE_LEN: usize = 64 * 1024;

fn sample_file(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("theviewer-ui-{}-{name}.bin", std::process::id()));
    // 64-byte records: two marker bytes, a counter, then a random payload.
    let mut state = 0x9E37_79B9u32;
    let bytes: Vec<u8> = (0..SAMPLE_LEN)
        .map(|i| match i % 64 {
            0 => 0xAA,
            1 => 0x55,
            2 => (i / 64) as u8,
            _ => {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            }
        })
        .collect();
    std::fs::write(&path, bytes).unwrap();
    path
}

fn harness(path: PathBuf) -> Harness<'static, ViewerApp> {
    let launch = Launch { path: Some(path), width: Some(64), zoom: Some(4.0), ..Default::default() };
    let mut harness = Harness::builder()
        .with_size(egui::vec2(1400.0, 900.0))
        .build_eframe(move |creation| {
            theviewer::theme::apply(&creation.egui_ctx);
            ViewerApp::new(launch)
        });
    for _ in 0..3 {
        harness.step();
    }
    harness
}

fn steps(harness: &mut Harness<'static, ViewerApp>, count: usize) {
    for _ in 0..count {
        harness.step();
    }
}

/// A point inside the raster image, wherever its pane is.
fn raster_point(harness: &Harness<'static, ViewerApp>) -> egui::Pos2 {
    let rect = harness.state().raster_rect.expect("the raster has been drawn");
    pos2(rect.min.x + 40.0, rect.min.y + rect.height() * 0.4)
}

fn click_at(harness: &mut Harness<'static, ViewerApp>, pos: egui::Pos2, modifiers: Modifiers) {
    harness.hover_at(pos);
    harness.step();
    harness.event(Event::PointerButton { pos, button: PointerButton::Primary, pressed: true, modifiers });
    harness.step();
    harness.event(Event::PointerButton { pos, button: PointerButton::Primary, pressed: false, modifiers });
    steps(harness, 2);
}

#[test]
fn opens_a_file_and_renders_without_panicking() {
    let mut harness = harness(sample_file("open"));
    assert_eq!(harness.state().document.len(), SAMPLE_LEN);
    assert!(harness.state().last_raster_pixels > 0);
    steps(&mut harness, 5);
}

#[test]
fn clicking_the_raster_moves_the_cursor_to_that_byte() {
    let mut harness = harness(sample_file("click"));
    let point = raster_point(&harness);
    click_at(&mut harness, point, Modifiers::NONE);
    let cursor = harness.state().cursor;
    assert!(cursor > 0 && cursor < SAMPLE_LEN, "cursor {cursor}");
    assert!(harness.state().selection().is_none());
}

#[test]
fn dragging_in_the_raster_selects_a_range() {
    let mut harness = harness(sample_file("drag"));
    let start = raster_point(&harness);
    drag(&mut harness, start, pos2(start.x + 60.0, start.y + 20.0));
    let (_, len) = harness.state().selection().expect("a selection after dragging");
    assert!(len > 1, "selection length {len}");
}

#[test]
fn typing_hex_overwrites_the_byte_and_undo_restores_it() {
    let mut harness = harness(sample_file("type"));
    let point = raster_point(&harness);
    click_at(&mut harness, point, Modifiers::NONE);
    let cursor = harness.state().cursor;
    let original = harness.state_mut().document.byte_at(cursor).unwrap();
    let replacement = !original;
    let digits = format!("{replacement:02x}");

    harness.event(Event::Text(digits[..1].to_string()));
    harness.step();
    harness.event(Event::Text(digits[1..].to_string()));
    steps(&mut harness, 2);
    assert_eq!(harness.state_mut().document.byte_at(cursor), Some(replacement));
    assert_eq!(harness.state().cursor, cursor + 1, "cursor advances after a full byte");
    assert_eq!(harness.state().document.len(), SAMPLE_LEN, "overwrite keeps the length");

    harness.key_press_modifiers(Modifiers::COMMAND, Key::Z);
    steps(&mut harness, 2);
    assert_eq!(harness.state_mut().document.byte_at(cursor), Some(original));
}

#[test]
fn insert_mode_grows_the_document_when_typing() {
    let mut harness = harness(sample_file("insert"));
    let point = raster_point(&harness);
    click_at(&mut harness, point, Modifiers::NONE);
    harness.key_press(Key::Insert);
    steps(&mut harness, 2);
    assert_eq!(harness.state().edit_mode, EditMode::Insert);
    harness.event(Event::Text("a".into()));
    harness.step();
    harness.event(Event::Text("b".into()));
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), SAMPLE_LEN + 1);
}

#[test]
fn arrow_keys_move_the_cursor_by_pixel_and_row() {
    let mut harness = harness(sample_file("arrows"));
    let stride = harness.state().shape.row_stride();
    harness.key_press(Key::ArrowRight);
    steps(&mut harness, 2);
    assert_eq!(harness.state().cursor, 1);
    harness.key_press(Key::ArrowDown);
    steps(&mut harness, 2);
    assert_eq!(harness.state().cursor, 1 + stride);
    harness.key_press_modifiers(Modifiers::SHIFT, Key::ArrowRight);
    steps(&mut harness, 2);
    assert_eq!(harness.state().selection(), Some((1 + stride, 1)));
    harness.key_press(Key::Escape);
    steps(&mut harness, 2);
    assert!(harness.state().selection().is_none());
}

#[test]
fn delete_key_removes_the_byte_and_backspace_the_previous_one() {
    let mut harness = harness(sample_file("delete"));
    harness.key_press(Key::ArrowRight);
    harness.key_press(Key::ArrowRight);
    steps(&mut harness, 2);
    harness.key_press(Key::Delete);
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), SAMPLE_LEN - 1);
    harness.key_press(Key::Backspace);
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), SAMPLE_LEN - 2);
    assert_eq!(harness.state().cursor, 1);
}

#[test]
fn toolbar_buttons_run_their_operations() {
    let mut harness = harness(sample_file("toolbar"));
    let point = raster_point(&harness);
    click_at(&mut harness, point, Modifiers::NONE);
    let cursor = harness.state().cursor;
    let original = harness.state_mut().document.byte_at(cursor).unwrap();

    harness.get_by_label("Invert").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state_mut().document.byte_at(cursor), Some(!original));

    harness.get_by_label("Mirror bits").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state_mut().document.byte_at(cursor), Some((!original).reverse_bits()));

    // Every toolbar control must be on screen, whatever the window width.
    let undo_rect = harness.get_by_label("Undo").rect();
    assert!(undo_rect.max.x <= 1400.0, "Undo is off screen at {undo_rect:?}");
    harness.get_by_label("Undo").click();
    steps(&mut harness, 2);
    harness.get_by_label("Undo").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state_mut().document.byte_at(cursor), Some(original));

    harness.get_by_label("Redo").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state_mut().document.byte_at(cursor), Some(!original));

    harness.get_by_label("Reverse").click();
    steps(&mut harness, 2);
    harness.get_by_label("Fill").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state_mut().document.byte_at(cursor), Some(0x00), "default fill pattern is 00");

    harness.get_by_label("Delete").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), SAMPLE_LEN - 1);

    harness.get_by_label("Insert").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), SAMPLE_LEN);

    let zoom = harness.state().zoom;
    harness.get_by_label("+").click();
    steps(&mut harness, 2);
    assert!(harness.state().zoom > zoom);
    harness.get_by_label("-").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state().zoom, zoom);

    harness.get_by_label("Fit").click();
    steps(&mut harness, 3);
    assert!(harness.state().shape.width > 64);

    harness.get_by_label("To cursor").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state().shape.byte_offset, harness.state().cursor);

    harness.key_press(Key::Questionmark);
    steps(&mut harness, 2);
    assert!(harness.state().show_help);
    harness.key_press(Key::Escape);
    steps(&mut harness, 2);
    assert!(!harness.state().show_help);
}

#[test]
fn detect_width_finds_the_record_stride_and_applies_it() {
    let mut harness = harness(sample_file("detect"));
    harness.state_mut().shape.width = 100;
    harness.get_by_label("Detect width").click();
    steps(&mut harness, 2);
    assert!(harness.state().panel_is_open(theviewer::layout::Pane::PeriodChart));

    // Wait for the background scan.
    let started = std::time::Instant::now();
    while harness.state().scan_pending && started.elapsed().as_secs() < 10 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        harness.step();
    }
    let scan = harness.state().period_scan.clone().expect("a finished scan");
    let best = scan.candidates.first().expect("a candidate").period;
    assert_eq!(best, 64, "candidates: {:?}", scan.candidates);

    harness.state_mut().apply_period(best);
    steps(&mut harness, 2);
    assert_eq!(harness.state().shape.width, 64);
    assert_eq!(harness.state().shape.row_padding, 0);

    // A period that is not a whole number of pixels becomes width + padding.
    harness.state_mut().shape.format = PixelFormat::Rgb8;
    harness.state_mut().apply_period(64);
    steps(&mut harness, 2);
    assert_eq!(harness.state().shape.width, 21);
    assert_eq!(harness.state().shape.row_padding, 1);
}

#[test]
fn every_format_palette_and_extreme_shape_renders() {
    let mut harness = harness(sample_file("formats"));
    for format in PixelFormat::ALL {
        for palette in Palette::ALL {
            harness.state_mut().shape.format = format;
            harness.state_mut().shape.palette = palette;
            steps(&mut harness, 1);
        }
    }
    let len = harness.state().document.len();
    let extremes = [
        (1usize, 0usize, 0u32, 0usize),
        (16384, 0, 0, 0),
        (64, len, 0, 0),
        (64, len - 1, 7, 0),
        (64, 3, 5, 1000),
        (7, 0, 1, 0),
    ];
    for (width, offset, bit, padding) in extremes {
        for format in [PixelFormat::Bit1Msb, PixelFormat::Nibble4, PixelFormat::Gray8, PixelFormat::Rgb8, PixelFormat::Rgba8] {
            let app = harness.state_mut();
            app.shape.format = format;
            app.shape.width = width;
            app.shape.byte_offset = offset;
            app.shape.bit_offset = bit;
            app.shape.row_padding = padding;
            steps(&mut harness, 2);
            let point = raster_point(&harness);
            click_at(&mut harness, point, Modifiers::NONE);
            let point = raster_point(&harness);
            click_at(&mut harness, point, Modifiers::SHIFT);
            harness.key_press(Key::ArrowDown);
            harness.key_press(Key::PageDown);
            harness.key_press(Key::End);
            steps(&mut harness, 2);
        }
    }
    for zoom in [0.125f32, 48.0] {
        harness.state_mut().zoom = zoom;
        steps(&mut harness, 2);
        let point = raster_point(&harness);
        click_at(&mut harness, point, Modifiers::NONE);
    }
}

#[test]
fn an_empty_document_survives_clicks_and_keys() {
    let launch = Launch::default();
    let mut harness = Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_eframe(move |creation| {
            theviewer::theme::apply(&creation.egui_ctx);
            ViewerApp::new(launch)
        });
    steps(&mut harness, 3);
    let point = raster_point(&harness);
    click_at(&mut harness, point, Modifiers::NONE);
    for key in [Key::ArrowRight, Key::ArrowDown, Key::Delete, Key::Backspace, Key::End, Key::PageDown] {
        harness.key_press(key);
        steps(&mut harness, 1);
    }
    harness.event(Event::Text("a".into()));
    harness.event(Event::Text("b".into()));
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), 1, "typing into an empty document appends a byte");
    harness.get_by_label("Invert").click();
    harness.get_by_label("Fit").click();
    steps(&mut harness, 2);
}

#[test]
fn copy_cut_paste_round_trip_bytes() {
    let mut harness = harness(sample_file("clipboard"));
    harness.key_press_modifiers(Modifiers::SHIFT, Key::ArrowRight);
    harness.key_press_modifiers(Modifiers::SHIFT, Key::ArrowRight);
    steps(&mut harness, 2);
    assert_eq!(harness.state().selection(), Some((0, 2)));
    harness.key_press_modifiers(Modifiers::COMMAND, Key::X);
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), SAMPLE_LEN - 2);
    assert_eq!(harness.state().clipboard, vec![0xAA, 0x55]);
    harness.key_press(Key::End);
    harness.key_press_modifiers(Modifiers::COMMAND, Key::V);
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), SAMPLE_LEN);
    assert_eq!(harness.state_mut().document.read_range(SAMPLE_LEN - 2, 2), vec![0xAA, 0x55]);
}

#[test]
fn pattern_highlights_find_the_counter_and_can_be_selected() {
    let mut harness = harness(sample_file("patterns"));
    harness.state_mut().shape.width = 64;
    let started = std::time::Instant::now();
    while harness.state().patterns.is_empty() && started.elapsed().as_secs() < 10 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        harness.step();
    }
    let patterns = harness.state().patterns.clone();
    // The sample has a u8 counter at offset 2 of every 64-byte record.
    let counter = patterns
        .iter()
        .find(|p| p.category == theviewer::plugin::Category::Counter && p.sequence.map(|s| s.stride) == Some(64) && p.start == 2)
        .unwrap_or_else(|| {
            let counters: Vec<_> = patterns.iter().filter(|p| p.category == theviewer::plugin::Category::Counter).collect();
            panic!("stride-64 counter in {counters:?}")
        });
    assert!(counter.sequence.unwrap().count >= 200, "{counter:?}");
    assert!(harness.state().pattern_at(2).is_some());

    // Selecting a pattern selects exactly its bytes.
    let chosen = counter.clone();
    harness.state_mut().select_pattern(&chosen);
    steps(&mut harness, 2);
    assert_eq!(harness.state().selection(), Some((chosen.start, chosen.len)));

    // Highlights start off, yet the pattern was still found. The toggle only
    // shows or hides the colours; detection carries on either way.
    assert!(!harness.state().highlight_patterns, "highlights are off by default");
    harness.key_press(Key::H);
    steps(&mut harness, 2);
    assert!(harness.state().highlight_patterns);
    harness.key_press(Key::H);
    steps(&mut harness, 2);
    assert!(!harness.state().highlight_patterns);
    assert!(harness.state().pattern_at(2).is_some(), "hiding highlights keeps the findings");
    harness.state_mut().pattern_list_open = true;
    steps(&mut harness, 3);
    harness.get_by_label("Kinds").click();
    steps(&mut harness, 2);
}



/// A point inside the hex dump's rows (over a hex cell), wherever its pane is.
fn hex_point(harness: &Harness<'static, ViewerApp>) -> egui::Pos2 {
    let rect = harness.state().hex_body_rect.expect("the hex dump has been drawn");
    pos2(rect.min.x + rect.width() * 0.35, rect.min.y + rect.height() * 0.5)
}

/// Step until egui has finished smoothing any wheel input, as a person would
/// wait for scrolling to stop before reading the screen.
fn settle(harness: &mut Harness<'static, ViewerApp>) {
    for _ in 0..200 {
        harness.step();
        if harness.ctx.input(|i| i.smooth_scroll_delta == egui::Vec2::ZERO) {
            break;
        }
    }
    steps(harness, 2);
}

fn scroll_at(harness: &mut Harness<'static, ViewerApp>, pos: egui::Pos2, delta_y: f32) {
    harness.hover_at(pos);
    harness.step();
    harness.event(Event::MouseWheel { unit: egui::MouseWheelUnit::Point, delta: egui::vec2(0.0, delta_y), phase: egui::TouchPhase::Move, modifiers: Modifiers::NONE });
    settle(harness);
}

#[test]
fn hex_and_raster_views_track_each_other() {
    let mut harness = harness(sample_file("linked"));
    // Keep the raster at 64 bytes per row and 4x so a screen is a few KiB.
    harness.state_mut().shape.width = 64;
    steps(&mut harness, 2);
    let stride = harness.state().shape.row_stride();

    // Scrolling the raster far down moves the hex dump with it.
    let point = raster_point(&harness);
    scroll_at(&mut harness, point, -4000.0);
    let top_row = harness.state().top_row;
    assert!(top_row > 10, "raster scrolled to row {top_row}");
    let raster_first = top_row * stride;
    assert_eq!(harness.state().hex_top_row, raster_first / 16, "hex dump follows the raster origin");

    // Scrolling the hex dump moves the raster to match.
    let point = hex_point(&harness);
    scroll_at(&mut harness, point, 800.0);
    let hex_top = harness.state().hex_top_row;
    assert!(hex_top < raster_first / 16, "hex scrolled up to row {hex_top}");
    assert_eq!(harness.state().top_row, (hex_top * 16) / stride, "raster follows the hex dump");

    // Hovering the hex dump reports the byte under the pointer to the raster.
    harness.hover_at(hex_point(&harness));
    settle(&mut harness);
    let hovered = harness.state().hover.expect("hover from the hex dump");
    let (hex_top, hex_rows) = (harness.state().hex_top_row, harness.state().hex_visible_rows);
    assert!(hovered >= hex_top * 16 && hovered < (hex_top + hex_rows) * 16, "hovered {hovered} in rows {hex_top}+{hex_rows}");

    // Clicking in the hex dump places the cursor there and brings it into the raster view.
    harness.state_mut().top_row = 900;
    steps(&mut harness, 2);
    let point = hex_point(&harness);
    click_at(&mut harness, point, Modifiers::NONE);
    let cursor = harness.state().cursor;
    assert_eq!(cursor, hovered, "clicked byte becomes the cursor");
    let row = harness.state().raster_row_of(cursor).unwrap();
    let app = harness.state();
    assert!(row >= app.top_row && row < app.top_row + app.visible_rows, "raster scrolled to show the cursor");

    // Clicking in the raster far from the hex window brings the hex dump to the cursor.
    harness.state_mut().top_row = 0;
    steps(&mut harness, 2);
    let point = raster_point(&harness);
    click_at(&mut harness, point, Modifiers::NONE);
    let cursor = harness.state().cursor;
    let app = harness.state();
    assert!(cursor / 16 >= app.hex_top_row && cursor / 16 < app.hex_top_row + app.hex_visible_rows, "hex dump shows the cursor");
    assert!(harness.state().hover.is_some(), "hover from the raster");
}



#[test]
fn compressed_blocks_are_found_decompressed_and_recompressed() {
    use theviewer::compress::{self, Codec};
    use theviewer::plugin::Category;

    // A file with a zlib stream buried between zero padding.
    let mut text = Vec::new();
    for i in 0..3000 {
        text.extend_from_slice(format!("event {i:05} temperature=21.5 status=ok\n").as_bytes());
    }
    let packed = compress::compress(Codec::Zlib, &text).unwrap();
    let mut file = vec![0u8; 512];
    let stream_at = file.len();
    file.extend_from_slice(&packed);
    file.extend_from_slice(&[0u8; 512]);
    let path = std::env::temp_dir().join(format!("theviewer-ui-{}-zlib.bin", std::process::id()));
    std::fs::write(&path, &file).unwrap();
    let file_len = file.len();

    let mut harness = harness(path);
    let started = std::time::Instant::now();
    while !harness.state().patterns.iter().any(|p| p.category == Category::Compressed) && started.elapsed().as_secs() < 10 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        harness.step();
    }
    let stream = harness
        .state()
        .patterns
        .iter()
        .find(|p| p.category == Category::Compressed)
        .cloned()
        .expect("a verified zlib stream");
    assert_eq!((stream.start, stream.len), (stream_at, packed.len()));
    assert!(stream.description().starts_with("zlib stream"), "{}", stream.description());

    // Clicking anywhere inside the stream and decompressing opens its contents.
    harness.state_mut().set_cursor(stream_at + 100, false);
    steps(&mut harness, 2);
    assert!(harness.state().compressed_stream_at_cursor().is_some());
    harness.get_by_label("Decompress").click();
    steps(&mut harness, 3);
    assert_eq!(harness.state().document.len(), text.len(), "status: {}", harness.state().status);
    assert_eq!(harness.state_mut().document.read_range(0, 40), text[..40]);
    assert!(harness.state().display_name().contains("zlib@0x200"), "{}", harness.state().display_name());
    assert_eq!(harness.state().parents.len(), 1);

    // Back restores the parent with the cursor where it was.
    harness.key_press_modifiers(Modifiers::COMMAND, Key::OpenBracket);
    steps(&mut harness, 3);
    assert_eq!(harness.state().document.len(), file_len);
    assert_eq!(harness.state().cursor, stream_at + 100);
    assert!(harness.state().parents.is_empty());

    // In place replaces the exact extent, undo restores it.
    harness.get_by_label("In place").click();
    steps(&mut harness, 3);
    assert_eq!(harness.state().document.len(), file_len - packed.len() + text.len());
    assert_eq!(harness.state().selection(), Some((stream_at, text.len())));
    harness.key_press_modifiers(Modifiers::COMMAND, Key::Z);
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), file_len);

    // Compress a selection with gzip, then decompress it in place again.
    harness.state_mut().anchor = Some(0);
    harness.state_mut().cursor = 512;
    harness.state_mut().compress_selection(Codec::Gzip);
    steps(&mut harness, 2);
    let gz = compress::compress(Codec::Gzip, &vec![0u8; 512]).unwrap();
    assert_eq!(harness.state().document.len(), file_len - 512 + gz.len());
    harness.state_mut().set_cursor(0, false);
    harness.state_mut().decompress_in_place();
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), file_len);
    assert_eq!(harness.state_mut().document.read_range(0, 512), vec![0u8; 512]);

    // Probing plain bytes says so.
    harness.state_mut().set_cursor(10, false);
    harness.state_mut().probe_at_cursor();
    assert!(harness.state().status.starts_with("Nothing decodes"), "{}", harness.state().status);
}


#[test]
fn flipping_extracting_and_repacking_a_stream() {
    use theviewer::compress::{self, Codec};
    use theviewer::plugin::Category;

    let text: Vec<u8> = (0..2000).flat_map(|i| format!("sample {i:04} payload\n").into_bytes()).collect();
    let packed = compress::compress(Codec::Bzip2, &text).unwrap();
    let mut file = vec![0xAAu8; 256];
    let stream_at = file.len();
    file.extend_from_slice(&packed);
    file.extend_from_slice(&[0x55u8; 256]);
    let dir = std::env::temp_dir();
    let path = dir.join(format!("theviewer-ui-{}-flip.bin", std::process::id()));
    std::fs::write(&path, &file).unwrap();

    let mut harness = harness(path);
    let started = std::time::Instant::now();
    while !harness.state().patterns.iter().any(|p| p.category == Category::Compressed) && started.elapsed().as_secs() < 10 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        harness.step();
    }
    harness.state_mut().set_cursor(stream_at + 10, false);
    steps(&mut harness, 2);

    // Cmd+D flips in, Cmd+D flips back out.
    harness.key_press_modifiers(Modifiers::COMMAND, Key::D);
    steps(&mut harness, 3);
    assert_eq!(harness.state().document.len(), text.len(), "{}", harness.state().status);
    assert!(harness.get_by_label("Back to compressed").rect().width() > 0.0);
    harness.key_press_modifiers(Modifiers::COMMAND, Key::D);
    steps(&mut harness, 3);
    assert_eq!(harness.state().document.len(), file.len());
    assert_eq!(harness.state().cursor, stream_at + 10);

    // Select stream picks exactly the compressed bytes; extraction writes them out.
    harness.get_by_label("Select stream").click();
    steps(&mut harness, 2);
    assert_eq!(harness.state().selection(), Some((stream_at, packed.len())));
    let raw_out = dir.join(format!("theviewer-ui-{}-raw.bz2", std::process::id()));
    harness.state_mut().export_bytes_to(&raw_out);
    assert_eq!(std::fs::read(&raw_out).unwrap(), packed);
    let text_out = dir.join(format!("theviewer-ui-{}-text.bin", std::process::id()));
    harness.state_mut().export_decompressed_to(&text_out);
    assert_eq!(std::fs::read(&text_out).unwrap(), text);
    std::fs::remove_file(raw_out).ok();
    std::fs::remove_file(text_out).ok();

    // Without a selection, extraction falls back to the stream under the cursor.
    harness.state_mut().set_cursor(stream_at + 5, false);
    let raw_out = dir.join(format!("theviewer-ui-{}-raw2.bz2", std::process::id()));
    harness.state_mut().export_bytes_to(&raw_out);
    assert_eq!(std::fs::read(&raw_out).unwrap(), packed);
    std::fs::remove_file(raw_out).ok();

    // In place, edit, re-pack with the same codec, and the file still decodes.
    harness.get_by_label("In place").click();
    steps(&mut harness, 3);
    assert_eq!(harness.state().inplace_codec, Some(Codec::Bzip2));
    assert_eq!(harness.state().selection(), Some((stream_at, text.len())));
    harness.state_mut().document.overwrite(stream_at, b"EDITED");
    harness.state_mut().restore_selection(stream_at, text.len());
    steps(&mut harness, 2);
    harness.get_by_label("Re-pack as bzip2").click();
    steps(&mut harness, 3);
    let (start, len) = harness.state().selection().expect("re-packed selection");
    assert_eq!(start, stream_at);
    let repacked = harness.state_mut().document.read_range(start, len);
    let unpacked = compress::decompress(Codec::Bzip2, &repacked, usize::MAX).unwrap();
    assert!(unpacked.data.starts_with(b"EDITED"));
    assert_eq!(unpacked.data.len(), text.len());
    assert_eq!(harness.state().document.len(), file.len() - packed.len() + len);
}

#[test]
fn search_palette_and_bookmarks_work_end_to_end() {
    use theviewer::search::SearchMode;

    let path = sample_file("search");
    let mut harness = harness(path.clone());
    // Find the record marker bytes AA 55 by hex; next and previous move between records.
    harness.state_mut().search_mode = SearchMode::Hex;
    harness.state_mut().search_text = "AA 55".to_string();
    harness.state_mut().find_next();
    assert_eq!(harness.state().selection(), Some((0, 2)), "{}", harness.state().status);
    harness.key_press(Key::F3);
    steps(&mut harness, 2);
    assert_eq!(harness.state().selection(), Some((64, 2)));
    harness.key_press_modifiers(Modifiers::SHIFT, Key::F3);
    steps(&mut harness, 2);
    assert_eq!(harness.state().selection(), Some((0, 2)));
    // 1024 record markers, plus any the random payload happens to contain.
    assert!(harness.state().search_count.is_some_and(|count| count >= 1024), "{:?}", harness.state().search_count);

    // Integer search finds the counter value 7 at record 7.
    harness.state_mut().search_mode = SearchMode::Integer;
    harness.state_mut().search_text = "0xAA55".to_string();
    harness.state_mut().search_little_endian = false;
    harness.state_mut().search_count = None;
    harness.state_mut().set_cursor(100, false);
    harness.state_mut().find_next();
    assert_eq!(harness.state().selection(), Some((128, 2)));

    // Command palette: open, type, run.
    harness.key_press_modifiers(Modifiers::COMMAND, Key::K);
    steps(&mut harness, 2);
    assert!(harness.state().palette.open);
    harness.state_mut().palette.query = "zoom in".to_string();
    let zoom = harness.state().zoom;
    steps(&mut harness, 2);
    harness.key_press(Key::Enter);
    steps(&mut harness, 3);
    assert!(!harness.state().palette.open);
    assert!(harness.state().zoom > zoom, "palette ran Zoom in");

    // Bookmarks: add via the API, navigate, persist to the sidecar, reload.
    harness.state_mut().add_bookmark(64, 2, "second record".to_string());
    harness.state_mut().add_bookmark(640, 0, "tenth".to_string());
    harness.state_mut().set_cursor(0, false);
    harness.key_press(Key::F2);
    steps(&mut harness, 2);
    assert_eq!(harness.state().selection(), Some((64, 2)));
    harness.key_press(Key::F2);
    steps(&mut harness, 2);
    assert_eq!(harness.state().cursor, 640);
    harness.key_press(Key::F2);
    steps(&mut harness, 2);
    assert_eq!(harness.state().selection(), Some((64, 2)), "wraps around");
    let sidecar = theviewer::bookmarks::sidecar_path(&path);
    assert!(sidecar.exists());
    harness.state_mut().shape.width = 96;
    harness.state_mut().save_sidecar();
    harness.state_mut().load_path(&path);
    steps(&mut harness, 2);
    assert_eq!(harness.state().bookmarks.bookmarks.len(), 2);
    assert_eq!(harness.state().shape.width, 96, "shape remembered");
    harness.state_mut().remove_bookmark(64);
    harness.state_mut().remove_bookmark(640);
    // The sidecar keeps the remembered shape, but no bookmarks.
    let saved = theviewer::bookmarks::load(&sidecar).unwrap();
    assert!(saved.bookmarks.is_empty());
    assert!(saved.shape.is_some());

    // The bookmark prompt opens on Cmd+B and commits with Enter.
    harness.key_press_modifiers(Modifiers::COMMAND, Key::B);
    steps(&mut harness, 2);
    assert!(harness.state().bookmark_prompt.is_some());
    harness.state_mut().bookmark_prompt = Some((0, 0, "typed name".to_string()));
    steps(&mut harness, 1);
    harness.key_press(Key::Enter);
    steps(&mut harness, 3);
    assert_eq!(harness.state().bookmarks.bookmarks.len(), 1);
    assert_eq!(harness.state().bookmarks.bookmarks[0].name, "typed name");
    std::fs::remove_file(&sidecar).ok();
}

#[test]
fn embedded_images_audio_and_video_open_in_the_media_window() {
    use theviewer::media::MediaKind;

    // A PNG, a WAV and (when ffmpeg is installed) an MP4, separated by padding.
    let png = {
        let image = image::RgbaImage::from_fn(40, 30, |x, y| image::Rgba([x as u8 * 6, y as u8 * 8, 90, 255]));
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image).write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    };
    let wav = {
        let rate = 8000u32;
        let data: Vec<u8> = (0..rate).flat_map(|n| (((n as f32 * 0.35).sin() * 12000.0) as i16).to_le_bytes()).collect();
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00");
        wav.extend_from_slice(&rate.to_le_bytes());
        wav.extend_from_slice(&(rate * 2).to_le_bytes());
        wav.extend_from_slice(b"\x02\x00\x10\x00data");
        wav.extend_from_slice(&(data.len() as u32).to_le_bytes());
        wav.extend_from_slice(&data);
        wav
    };
    let dir = std::env::temp_dir();
    let mp4 = if theviewer::media::ffmpeg_available() {
        let clip = dir.join(format!("theviewer-ui-{}-clip.mp4", std::process::id()));
        let ok = std::process::Command::new("ffmpeg")
            .args(["-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=64x48:rate=10", "-t", "1", "-pix_fmt", "yuv420p"])
            .arg(&clip)
            .status()
            .is_ok_and(|s| s.success());
        let bytes = if ok { std::fs::read(&clip).ok() } else { None };
        std::fs::remove_file(&clip).ok();
        bytes
    } else {
        None
    };

    let mut file = vec![0u8; 512];
    let png_at = file.len();
    file.extend_from_slice(&png);
    file.extend_from_slice(&[0u8; 512]);
    let wav_at = file.len();
    file.extend_from_slice(&wav);
    file.extend_from_slice(&[0u8; 512]);
    let mp4_at = file.len();
    if let Some(mp4) = &mp4 {
        file.extend_from_slice(mp4);
    }
    let path = dir.join(format!("theviewer-ui-{}-media.bin", std::process::id()));
    std::fs::write(&path, &file).unwrap();
    let mut harness = harness(path);

    let wait_ready = |harness: &mut Harness<'static, ViewerApp>| {
        let started = std::time::Instant::now();
        while !harness.state().media.is_ready() && harness.state().media.error().is_none() && started.elapsed().as_secs() < 15 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            harness.step();
        }
    };

    let started = std::time::Instant::now();
    while harness.state().patterns.is_empty() && started.elapsed().as_secs() < 10 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        harness.step();
    }

    // Nothing to open on plain padding.
    harness.state_mut().set_cursor(10, false);
    steps(&mut harness, 2);
    harness.state_mut().open_media();
    assert!(!harness.state().media.is_open());

    // Image: Cmd+Enter with the cursor inside the PNG.
    harness.state_mut().set_cursor(png_at + 20, false);
    steps(&mut harness, 3);
    harness.key_press_modifiers(Modifiers::COMMAND, Key::Enter);
    steps(&mut harness, 2);
    wait_ready(&mut harness);
    assert_eq!(harness.state().media.kind(), Some(MediaKind::Image), "{}", harness.state().status);
    assert!(harness.state().media.is_ready(), "{:?}", harness.state().media.error());

    // Audio: opened from the start of the WAV, analysed to its one-second length.
    harness.state_mut().set_cursor(wav_at, false);
    steps(&mut harness, 2);
    harness.state_mut().open_media();
    wait_ready(&mut harness);
    assert_eq!(harness.state().media.kind(), Some(MediaKind::Audio));
    let duration = harness.state().media.duration().expect("audio duration");
    assert!((duration.as_secs_f64() - 1.0).abs() < 0.05, "{duration:?}");
    assert!(!harness.state().media.is_playing(), "audio does not start by itself");

    // Video: first frame decoded through ffmpeg.
    if mp4.is_some() {
        harness.state_mut().set_cursor(mp4_at + 100, false);
        steps(&mut harness, 2);
        harness.state_mut().open_media();
        wait_ready(&mut harness);
        assert_eq!(harness.state().media.kind(), Some(MediaKind::Video));
        assert!(harness.state().media.is_ready(), "{:?}", harness.state().media.error());
        let duration = harness.state().media.duration().unwrap();
        assert!((duration.as_secs_f64() - 1.0).abs() < 0.1, "{duration:?}");
    }

    harness.state_mut().media.close();
    steps(&mut harness, 2);
    assert!(!harness.state().media.is_open());
}

#[test]
fn a_png_larger_than_the_scan_window_still_opens_whole() {
    // A noisy 700×700 PNG is well over a megabyte, far more than one scan window.
    let mut state = 0x1234_5678u32;
    let image = image::RgbImage::from_fn(700, 700, |_, _| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        image::Rgb([(state >> 24) as u8, (state >> 16) as u8, (state >> 8) as u8])
    });
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image).write_to(&mut png, image::ImageFormat::Png).unwrap();
    let png = png.into_inner();
    let mut file = vec![0u8; 4096];
    let png_at = file.len();
    file.extend_from_slice(&png);
    file.extend_from_slice(&[0u8; 4096]);
    let path = std::env::temp_dir().join(format!("theviewer-ui-{}-bigpng.bin", std::process::id()));
    std::fs::write(&path, &file).unwrap();

    let mut harness = harness(path);
    let started = std::time::Instant::now();
    while harness.state().patterns.is_empty() && started.elapsed().as_secs() < 10 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        harness.step();
    }

    harness.state_mut().set_cursor(png_at + 10, false);
    steps(&mut harness, 2);
    harness.state_mut().open_media();
    let started = std::time::Instant::now();
    while !harness.state().media.is_ready() && started.elapsed().as_secs() < 15 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        harness.step();
    }
    assert!(harness.state().media.is_ready(), "image did not decode: {:?}", harness.state().media.error_text());

    // The structure tree covers the whole PNG, not just the part in the scan window.
    let structure = harness.state().cursor_structure.clone().expect("a parsed structure at the cursor");
    assert_eq!(structure.start, png_at);
    assert_eq!(structure.len, png.len(), "{}", structure.description());
}

/// Captions of the toolbar groups that are always shown.
const TOOLBAR_CAPTIONS: [&str; 11] = [
    "Format", "Width (pixels per row)", "Origin", "Zoom", "Go to", "Find",
    "Insert at cursor", "Shift bits", "Move", "Typing", "Analysis",
];

fn caption_rects(harness: &Harness<'static, ViewerApp>) -> Vec<egui::Rect> {
    TOOLBAR_CAPTIONS
        .iter()
        .map(|caption| harness.get_by_label(caption).rect())
        .collect()
}

fn distinct_rows(rects: &[egui::Rect]) -> usize {
    let mut tops: Vec<f32> = rects.iter().map(|rect| rect.top().round()).collect();
    tops.sort_by(f32::total_cmp);
    tops.dedup();
    tops.len()
}

#[test]
fn toolbar_groups_pack_into_few_rows_without_overlapping() {
    // Wrapping in reading order took 5 rows at 1300 px; packed, the groups need 3.
    for (window_width, most_rows) in [(900.0, 5), (1300.0, 3), (1800.0, 2)] {
        let mut harness = harness(sample_file("toolbar.bin"));
        harness.set_size(egui::vec2(window_width, 900.0));
        steps(&mut harness, 6);
        let rects = caption_rects(&harness);
        for (index, rect) in rects.iter().enumerate() {
            assert!(rect.right() <= window_width, "{} runs off screen at {window_width}: {rect:?}", TOOLBAR_CAPTIONS[index]);
            for other in &rects[index + 1..] {
                assert!(!rect.intersects(*other), "captions overlap at {window_width}: {rect:?} {other:?}");
            }
        }
        let rows = distinct_rows(&rects);
        assert!(rows <= most_rows, "{rows} toolbar rows at {window_width} px, expected at most {most_rows}");
    }
}

fn drag(harness: &mut Harness<'static, ViewerApp>, from: egui::Pos2, to: egui::Pos2) {
    harness.hover_at(from);
    harness.step();
    harness.event(Event::PointerButton { pos: from, button: PointerButton::Primary, pressed: true, modifiers: Modifiers::NONE });
    harness.step();
    harness.event(Event::PointerMoved(from.lerp(to, 0.5)));
    harness.step();
    harness.event(Event::PointerMoved(to));
    harness.step();
    harness.event(Event::PointerButton { pos: to, button: PointerButton::Primary, pressed: false, modifiers: Modifiers::NONE });
    steps(harness, 4);
}

#[test]
fn toolbar_groups_can_be_dragged_into_a_new_order_and_reset() {
    let mut harness = harness(sample_file("reorder.bin"));
    steps(&mut harness, 4);
    let format = harness.get_by_label("Format").rect();
    let zoom = harness.get_by_label("Zoom").rect();
    assert!(zoom.left() > format.left(), "Zoom starts after Format");
    let (packed_format, packed_zoom) = (format, zoom);

    // Drag Zoom by its caption onto the left half of Format.
    drag(&mut harness, zoom.left_center() + egui::vec2(2.0, 0.0), format.left_center() + egui::vec2(4.0, 0.0));

    let rows = harness.state().toolbar_rows.clone().expect("the new order is remembered");
    let first_row = &rows[0];
    let zoom_index = first_row.iter().position(|key| key == "zoom").expect("zoom in the first row");
    let format_index = first_row.iter().position(|key| key == "format").expect("format in the first row");
    assert!(zoom_index < format_index, "{rows:?}");
    let format = harness.get_by_label("Format").rect();
    let zoom = harness.get_by_label("Zoom").rect();
    assert!(zoom.left() < format.left(), "Zoom is drawn before Format: {zoom:?} {format:?}");
    assert!((zoom.top() - format.top()).abs() < 1.0, "on the same row");

    // Forgetting the order packs automatically again.
    harness.state_mut().set_toolbar_rows(None);
    steps(&mut harness, 4);
    assert_eq!(harness.get_by_label("Format").rect(), packed_format, "automatic packing is back");
    assert_eq!(harness.get_by_label("Zoom").rect(), packed_zoom, "automatic packing is back");
}

#[test]
fn a_nonsense_zoom_factor_leaves_a_valid_zoom() {
    let mut harness = harness(sample_file("zoom-nan.bin"));
    harness.state_mut().apply_zoom_delta(f32::NAN);
    steps(&mut harness, 2);
    let zoom = harness.state().zoom;
    assert!(zoom.is_finite() && zoom > 0.0, "zoom {zoom}");
}

#[test]
fn drag_selections_include_both_the_first_and_last_byte_in_either_direction() {
    let mut harness = harness(sample_file("drag-ends.bin"));
    let app = harness.state_mut();
    let len = app.document.len();

    app.begin_drag_selection(0, false);
    app.drag_selection_to(3);
    app.end_drag_selection();
    assert_eq!(app.selection(), Some((0, 4)), "dragging right from 0 to 3");

    app.begin_drag_selection(5, false);
    app.drag_selection_to(2);
    app.end_drag_selection();
    assert_eq!(app.selection(), Some((2, 4)), "dragging left from 5 to 2");

    app.begin_drag_selection(len - 2, false);
    app.drag_selection_to(len - 1);
    app.end_drag_selection();
    assert_eq!(app.selection(), Some((len - 2, 2)), "the last byte can be selected");

    app.begin_drag_selection(7, false);
    app.drag_selection_to(9);
    app.drag_selection_to(7);
    app.end_drag_selection();
    assert_eq!(app.selection(), None, "ending where it started is a click");
    assert_eq!(app.cursor, 7);
}

#[test]
fn startup_defaults_from_settings_shape_a_new_window() {
    use theviewer::preferences::Preferences;
    let mut harness = harness(sample_file("preferences.bin"));
    let mut preferences = Preferences {
        highlight_patterns: true,
        format: "rgb8".into(),
        palette: "Viridis".into(),
        width: 96,
        zoom: 2.0,
        findings_list_open: false,
        ..Preferences::default()
    };
    preferences.set_kind_shown(theviewer::plugin::Category::Text, false);
    harness.state_mut().set_preferences(preferences);
    assert_eq!(harness.state().shape.width, 64, "saving defaults leaves the current view alone");

    harness.state_mut().apply_preferences();
    steps(&mut harness, 2);
    let app = harness.state();
    assert!(app.highlight_patterns);
    assert_eq!(app.shape.format, PixelFormat::Rgb8);
    assert_eq!(app.shape.palette, Palette::Viridis);
    assert_eq!(app.shape.width, 96);
    assert_eq!(app.zoom, 2.0);
    assert!(!app.pattern_list_open);
    assert!(!app.pattern_kind_enabled(theviewer::plugin::Category::Text));
    assert!(app.pattern_kind_enabled(theviewer::plugin::Category::Counter));
}

#[test]
fn the_settings_window_shows_the_startup_defaults() {
    let mut harness = harness(sample_file("settings.bin"));
    harness.state_mut().settings.open = true;
    steps(&mut harness, 3);
    harness.get_by_label("Highlight them in the view and hex dump").click();
    steps(&mut harness, 2);
    assert!(harness.state().preferences.highlight_patterns, "ticking the box changes the default");
    assert!(!harness.state().highlight_patterns, "but not the current window");
    harness.get_by_label("Apply to this window").click();
    steps(&mut harness, 2);
    assert!(harness.state().highlight_patterns);
}
