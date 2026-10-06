//! Headless tests for the dock's tools, driven through the real application.

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui::{self, Key, Modifiers};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use theviewer::app::{Launch, ViewerApp};
use theviewer::assistant::{self, ToolCall, ToolReply};
use theviewer::dock::DockTab;
use theviewer::media::MediaKind;
use theviewer::plugin::Category;

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("theviewer-tools-{}-{name}", std::process::id()))
}

fn harness_for(path: PathBuf) -> Harness<'static, ViewerApp> {
    let launch = Launch { path: Some(path), width: Some(64), zoom: Some(2.0), ..Default::default() };
    let mut harness = Harness::builder()
        .with_size(egui::vec2(1500.0, 1000.0))
        .build_eframe(move |creation| {
            theviewer::theme::apply(&creation.egui_ctx);
            ViewerApp::new(launch)
        });
    steps(&mut harness, 3);
    harness
}

/// Run one of Ask's tools against the window's document, as Ask does, and
/// take its answer.
fn run_ask_tool(app: &mut ViewerApp, tool: &str, input: serde_json::Value) -> Result<String, String> {
    let call = ToolCall::parse(tool, &input, &assistant::offered_tools(app)).unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    app.run_assistant_tool(call, ToolReply::new(sender));
    receiver.try_recv().expect("a tool that reads answers at once")
}

/// Run one of Ask's tools against the window's document and read its whole
/// JSON result (which the model gets cut to a length it can take).
fn ask_tool(app: &mut ViewerApp, tool: &str, input: serde_json::Value) -> serde_json::Value {
    let call = ToolCall::parse(tool, &input, &assistant::offered_tools(app)).unwrap();
    theviewer::api::call(app, &theviewer::api::Caller::Ask, &call.method, call.params).unwrap_or_else(|error| panic!("{tool}: {error}"))
}

fn steps(harness: &mut Harness<'static, ViewerApp>, count: usize) {
    for _ in 0..count {
        harness.step();
    }
}

/// Step until `done` holds or ten seconds pass.
fn wait_for(harness: &mut Harness<'static, ViewerApp>, done: impl Fn(&ViewerApp) -> bool) {
    let started = Instant::now();
    while !done(harness.state()) && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
        harness.step();
    }
}

fn xorshift_bytes(len: usize, mut state: u32) -> Vec<u8> {
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    theviewer::compress::compress(theviewer::compress::Codec::Gzip, data).unwrap()
}

/// A firmware-like file: text header, padding, a gzip stream, noise, a WAV.
fn composite_file() -> (Vec<u8>, usize, usize, usize) {
    let mut file = b"FWIMAGE v3.1 build 2026-10-05 for board rev C\n".to_vec();
    file.resize(256, 0);
    file.extend(std::iter::repeat_n(0xFFu8, 8192));
    let gzip_at = file.len();
    let text: Vec<u8> = (0..3000).flat_map(|i| format!("config line {i}\n").into_bytes()).collect();
    file.extend_from_slice(&gzip(&text));
    file.extend(xorshift_bytes(16384, 0xDEAD_BEEF));
    let wav_at = file.len();
    let mut wav = b"RIFF".to_vec();
    let data: Vec<u8> = (0..4000u32).flat_map(|n| (((n as f32 * 0.2).sin() * 9000.0) as i16).to_le_bytes()).collect();
    wav.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x40\x1f\x00\x00\x80\x3e\x00\x00\x02\x00\x10\x00data");
    wav.extend_from_slice(&(data.len() as u32).to_le_bytes());
    wav.extend_from_slice(&data);
    file.extend_from_slice(&wav);
    let len = file.len();
    (file, gzip_at, wav_at, len)
}

#[test]
fn every_dock_tab_renders_and_the_report_maps_the_file() {
    let (bytes, gzip_at, _, len) = composite_file();
    let path = temp_path("composite.bin");
    std::fs::write(&path, &bytes).unwrap();
    let mut harness = harness_for(path.clone());

    // The tools start expanded; Cmd+J collapses them and brings them back.
    harness.key_press_modifiers(Modifiers::COMMAND, Key::J);
    steps(&mut harness, 2);
    assert!(!harness.state().dock.open, "first press collapses the tools");
    harness.key_press_modifiers(Modifiers::COMMAND, Key::J);
    steps(&mut harness, 2);
    assert!(harness.state().dock.open, "second press expands them");
    for tab in DockTab::ALL {
        harness.state_mut().dock.tab = tab;
        steps(&mut harness, 3);
    }

    harness.state_mut().dock.tab = DockTab::Report;
    harness.state_mut().start_report();
    wait_for(&mut harness, |app| app.bench.report.is_some());
    let app = harness.state();
    let report = app.bench.report.as_ref().expect("a report");
    assert!(!report.headline.is_empty());
    let regions = &app.bench.regions;
    assert_eq!(regions.first().map(|r| r.start), Some(0));
    assert_eq!(regions.last().map(|r| r.end()), Some(len), "regions cover the file");
    assert!(regions.windows(2).all(|w| w[0].end() == w[1].start), "no gaps");
    assert!(regions.iter().any(|r| r.start == gzip_at && r.confident), "{regions:?}");
    steps(&mut harness, 3);

    // The file map is drawn, and the Hilbert layout renders and maps clicks.
    harness.state_mut().bench.layout = theviewer::workbench::Layout::Hilbert;
    steps(&mut harness, 3);
    harness.state_mut().bench.analysis.show_pointers = true;
    harness.state_mut().bench.layout = theviewer::workbench::Layout::Rows;
    steps(&mut harness, 3);
    std::fs::remove_file(path).ok();
}

#[test]
fn templates_apply_to_records_and_inference_recovers_a_counter() {
    // 64 records of 16 bytes: "REC1", u32 counter, u32 offset, u32 noise.
    let mut bytes = Vec::new();
    let noise = xorshift_bytes(64 * 4, 7);
    for i in 0..64u32 {
        bytes.extend_from_slice(b"REC1");
        bytes.extend_from_slice(&i.to_le_bytes());
        bytes.extend_from_slice(&(i * 16 + 4096).to_le_bytes());
        bytes.extend_from_slice(&noise[i as usize * 4..i as usize * 4 + 4]);
    }
    bytes.resize(8192, 0);
    let path = temp_path("records.bin");
    std::fs::write(&path, &bytes).unwrap();
    let mut harness = harness_for(path.clone());

    let source = "endian little\nstruct Rec {\n  magic: char[4] = \"REC1\"\n  index: u32\n  offset: u32 display hex\n  data: bytes[4]\n}\nroot Rec[64]\n";
    harness.state_mut().apply_template_source(source);
    steps(&mut harness, 3);
    let applied = harness.state().bench.template_result.clone().expect("template applied");
    assert_eq!(applied.records.len(), 64, "{:?}", applied.warnings);
    assert_eq!(applied.records[10].value("index"), Some("10"));
    assert_eq!(harness.state().cursor_structure.as_ref().map(|s| s.category), Some(Category::Structure));
    assert!(harness.state().patterns_in(0, 16).any(|f| f.id.starts_with("template:")), "pinned on the view");
    assert_eq!(harness.state().dock.tab, DockTab::Template);

    // A syntax error is reported with its line.
    harness.state_mut().apply_template_source("struct X {\n  a: u33\n}\nroot X\n");
    assert!(harness.state().bench.template_error.as_deref().is_some_and(|e| e.starts_with("line 2")), "{:?}", harness.state().bench.template_error);

    // Inference from a selection of records finds the counter.
    harness.state_mut().anchor = Some(0);
    harness.state_mut().cursor = 64 * 16;
    harness.state_mut().infer_template();
    steps(&mut harness, 3);
    let source = harness.state().bench.template_source.clone();
    assert!(source.contains("counter"), "{source}");
    let applied = harness.state().bench.template_result.clone().expect("inferred template applied");
    assert!(applied.records.len() >= 60, "{} records, warnings {:?}", applied.records.len(), applied.warnings);
    std::fs::remove_file(path).ok();
}

#[test]
fn unpacking_finds_nested_streams_and_opens_them() {
    let inner: Vec<u8> = (0..2000).flat_map(|i| format!("nested line {i}\n").into_bytes()).collect();
    let mut bytes = vec![0u8; 512];
    let outer_at = bytes.len();
    bytes.extend_from_slice(&gzip(&gzip(&inner)));
    bytes.extend_from_slice(&[0u8; 512]);
    let path = temp_path("nested.bin");
    std::fs::write(&path, &bytes).unwrap();
    let mut harness = harness_for(path.clone());

    harness.state_mut().start_unpack();
    wait_for(&mut harness, |app| app.bench.unpacked.is_some());
    let root = harness.state().bench.unpacked.clone().unwrap();
    let first = root.children.first().expect("the outer gzip stream");
    assert_eq!(first.source_offset, outer_at);
    let second = first.children.first().expect("the inner gzip stream");
    assert_eq!(second.data.as_slice(), inner.as_slice());

    // Opening a node descends into it; Back returns.
    harness.state_mut().open_derived(second.data.to_vec(), "inner".to_string());
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), inner.len());
    harness.state_mut().back_to_parent();
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), bytes.len());
    std::fs::remove_file(path).ok();
}

#[test]
fn disassembly_checksums_and_diff_work_from_the_dock() {
    // x86-64: push rbp; mov rbp, rsp; call +0; ret, then padding.
    let mut bytes = vec![0x55, 0x48, 0x89, 0xE5, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
    bytes.resize(4096, 0x90);
    bytes[2000..2005].copy_from_slice(b"hello");
    let path = temp_path("code.bin");
    std::fs::write(&path, &bytes).unwrap();
    let mut harness = harness_for(path.clone());

    harness.state_mut().dock.open = true;
    harness.state_mut().dock.tab = DockTab::Disassembly;
    harness.state_mut().bench.analysis.arch = theviewer::analysis_tabs::ArchChoice::Fixed(theviewer::disasm::Arch::X86_64);
    steps(&mut harness, 3);
    assert!(harness.query_by_label("push").is_some(), "listing shows push");
    assert!(harness.query_by_label("ret").is_some(), "listing shows ret");

    // Checksums of a selection.
    harness.state_mut().anchor = Some(2000);
    harness.state_mut().cursor = 2005;
    harness.state_mut().dock.tab = DockTab::Checksums;
    steps(&mut harness, 3);
    let digests = harness.state().bench.analysis.digests.clone().expect("digests").2;
    assert_eq!(digests.crc32, 0x3610_a686);
    assert_eq!(digests.md5, "5d41402abc4b2a76b9719d911017c592");
    // The tools pane is short in the default layout, so bring the button into view first.
    harness.get_by_label("Find the checksum").scroll_to_me();
    steps(&mut harness, 3);
    harness.get_by_label("Find the checksum").click();
    steps(&mut harness, 3);
    assert!(harness.state().bench.analysis.checksum_matches.is_some());

    // Diff against a copy with 100 bytes inserted.
    let mut other = bytes.clone();
    other.splice(3000..3000, std::iter::repeat_n(0xAB, 100));
    let other_path = temp_path("code-other.bin");
    std::fs::write(&other_path, &other).unwrap();
    harness.state_mut().dock.tab = DockTab::Diff;
    theviewer::analysis_tabs::start_diff(harness.state_mut(), other_path.clone());
    wait_for(&mut harness, |app| app.bench.analysis.diff.is_some());
    let result = harness.state().bench.analysis.diff.clone().unwrap();
    assert_eq!(result.changed_bytes, 100, "{:?}", result.ops);
    steps(&mut harness, 3);
    std::fs::remove_file(path).ok();
    std::fs::remove_file(other_path).ok();
}

#[test]
fn watch_mode_reloads_appended_bytes_and_records_history() {
    let path = temp_path("growing.log");
    std::fs::write(&path, b"first line\n").unwrap();
    let mut harness = harness_for(path.clone());
    harness.state_mut().bench.recording = Some(theviewer::sources::Recording::new(1 << 20));
    harness.state_mut().set_watch(true);
    assert!(harness.state().bench.watch_enabled, "{:?}", harness.state().bench.live_error);

    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"second line\n").unwrap();
    wait_for(&mut harness, |app| app.document.len() == 23);
    assert_eq!(harness.state().document.len(), 23);
    assert!(harness.state().patterns_in(11, 23).any(|f| f.id == "changed"), "appended bytes are highlighted");
    let recording = harness.state().bench.recording.as_ref().unwrap();
    assert_eq!(recording.len(), 2);
    assert_eq!(recording.materialise(0), b"first line\n");
    harness.state_mut().set_watch(false);
    std::fs::remove_file(path).ok();
}

#[test]
fn plotting_audio_from_bytes_and_the_assistant_tools() {
    let (bytes, gzip_at, wav_at, _) = composite_file();
    let path = temp_path("composite2.bin");
    std::fs::write(&path, &bytes).unwrap();
    let mut harness = harness_for(path.clone());

    harness.state_mut().anchor = Some(wav_at + 44);
    harness.state_mut().cursor = wav_at + 44 + 8000;
    harness.state_mut().open_plot();
    steps(&mut harness, 3);
    assert!(harness.state().plot.open);
    assert_eq!(harness.state().plot.bytes.len(), 8000);

    harness.state_mut().play_bytes_as_audio();
    steps(&mut harness, 2);
    assert_eq!(harness.state().media.kind(), Some(MediaKind::Audio));

    // The assistant's tools run against the open document.
    let app = harness.state_mut();
    let dump = ask_tool(app, "bytes_hexdump", serde_json::json!({ "start": 0, "len": 16 }));
    assert!(dump["dump"].as_str().unwrap().starts_with("00000000  46 57 49 4d"), "{dump}");
    let found = ask_tool(app, "search_find_all", serde_json::json!({ "query": "WAVE", "mode": "text" }));
    assert!(found["matches"].as_array().unwrap().contains(&serde_json::json!(wav_at + 8)), "{found}");
    let listed = ask_tool(app, "findings_query", serde_json::json!({ "start": gzip_at.saturating_sub(16), "len": 4096 }));
    assert!(listed.to_string().contains("gzip"), "{listed}");
    let parsed = ask_tool(app, "structure_parse", serde_json::json!({ "at": 1 }));
    assert_eq!(parsed["structures"], serde_json::json!([]), "nothing parses at offset 1");
    let refused = run_ask_tool(app, "bytes_hexdump", serde_json::json!({ "start": 1u64 << 40 }));
    assert!(refused.unwrap_err().contains("out_of_range"));

    // Without credentials, asking explains where to add a key.
    harness.state_mut().credentials = None;
    harness.state_mut().dock.question = "What is this?".to_string();
    harness.state_mut().ask_assistant();
    let last = harness.state().assistant.transcript.last().cloned();
    assert!(matches!(last, Some(theviewer::assistant::Turn::Note(ref note)) if note.contains("Settings")), "{last:?}");
    std::fs::remove_file(path).ok();
}

#[test]
fn opening_sources_reports_clear_errors() {
    let path = temp_path("plain.bin");
    std::fs::write(&path, b"plain").unwrap();
    let mut harness = harness_for(path.clone());
    harness.state_mut().open_source("pid:1");
    if !cfg!(target_os = "linux") {
        let error = harness.state().bench.live_error.clone().unwrap_or_default();
        assert!(error.contains("only supported on Linux"), "{error}");
    }
    harness.state_mut().open_source("http://127.0.0.1:9/nothing");
    wait_for(&mut harness, |app| !app.source_loading());
    assert!(harness.state().bench.live_error.is_some(), "an unreachable URL reports an error");
    std::fs::remove_file(path).ok();
}

#[test]
fn ask_is_greyed_out_until_a_key_is_saved_in_settings() {
    let path = temp_path("key.bin");
    std::fs::write(&path, b"some bytes").unwrap();
    let mut harness = harness_for(path.clone());
    // Use a private temporary store, never the real Keychain, and start keyless.
    let store_path = temp_path("credentials");
    harness.state_mut().settings.store = theviewer::settings::Store::File(store_path.clone());
    harness.state_mut().credentials = None;
    harness.state_mut().dock.open = true;
    harness.state_mut().dock.tab = DockTab::Assistant;
    steps(&mut harness, 3);
    assert!(!harness.state().assistant_available());
    harness.get_by_label("Add API key…").click();
    steps(&mut harness, 3);
    assert!(harness.state().settings.open, "the button opens Settings");
    // The same window opens from Cmd+, too.
    harness.state_mut().settings.open = false;
    harness.key_press_modifiers(Modifiers::COMMAND, Key::Comma);
    steps(&mut harness, 2);
    assert!(harness.state().settings.open);

    // A malformed key is refused; a well-formed one is saved and enables Ask.
    harness.state().settings.store.save("not-a-key").unwrap_err();
    if std::env::var("ANTHROPIC_API_KEY").is_err() {
        harness.state().settings.store.save("sk-ant-api03-testtesttesttesttest_ABCD").unwrap();
        harness.state_mut().refresh_credentials();
        steps(&mut harness, 3);
        assert!(harness.state().assistant_available());
        assert_eq!(harness.state().credentials.as_ref().map(|c| c.1.clone()), Some(theviewer::settings::KeySource::Saved));
        assert!(harness.query_by_label("Add API key…").is_none(), "the set-up card is gone");
        harness.state().settings.store.remove().unwrap();
        harness.state_mut().refresh_credentials();
        steps(&mut harness, 2);
        assert!(!harness.state().assistant_available() || std::env::var("ANTHROPIC_AUTH_TOKEN").is_ok());
    }
    std::fs::remove_file(path).ok();
    std::fs::remove_file(store_path).ok();
}

/// CRC-16/CCITT-FALSE, matching the protocol under test.
fn crc16_ccitt(bytes: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &byte in bytes {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

#[test]
fn columns_and_protocol_tabs_recover_structure() {
    // A message stream: sync AA 55, type, u16 BE sequence, u16 LE length, payload, CRC-16 BE.
    let noise = xorshift_bytes(64 * 1024, 99);
    let mut stream = Vec::new();
    let mut cursor = 0;
    for sequence in 0..400u16 {
        let payload_len = 4 + (noise[sequence as usize] as usize % 36);
        let mut body = vec![[1u8, 2, 3][sequence as usize % 3]];
        body.extend_from_slice(&sequence.to_be_bytes());
        body.extend_from_slice(&(payload_len as u16).to_le_bytes());
        body.extend_from_slice(&noise[cursor..cursor + payload_len]);
        cursor += payload_len;
        stream.extend_from_slice(&[0xAA, 0x55]);
        stream.extend_from_slice(&body);
        stream.extend_from_slice(&crc16_ccitt(&body).to_be_bytes());
    }
    let path = temp_path("protocol.bin");
    std::fs::write(&path, &stream).unwrap();
    let mut harness = harness_for(path.clone());

    harness.state_mut().dock.open = true;
    harness.state_mut().dock.tab = DockTab::Protocol;
    steps(&mut harness, 2);
    theviewer::analysis_tools::start_protocol(harness.state_mut());
    wait_for(&mut harness, |app| app.bench.tools.protocol.is_some());
    steps(&mut harness, 3);
    let view = harness.state().bench.tools.protocol.as_ref().unwrap();
    assert_eq!(view.report.messages.len(), 400, "{:?}", view.report.framing.as_ref().map(|f| f.framing.describe()));
    let kinds: Vec<String> = view.report.fields.iter().map(|f| f.kind.clone()).collect();
    for expected in ["message type", "sequence number", "length", "checksum"] {
        assert!(kinds.iter().any(|k| k.starts_with(expected)), "{expected} missing from {kinds:?}");
    }
    assert!(harness.state().patterns_in(0, 10).any(|f| f.id == "message"), "messages outlined on the view");

    // Columns: fixed 16-byte records with a counter.
    let mut records = Vec::new();
    for i in 0..256u32 {
        records.extend_from_slice(b"HDR1");
        records.extend_from_slice(&i.to_le_bytes());
        records.extend_from_slice(&noise[i as usize * 8..i as usize * 8 + 8]);
    }
    let records_path = temp_path("records16.bin");
    std::fs::write(&records_path, &records).unwrap();
    harness.state_mut().load_path(&records_path);
    harness.state_mut().bench.tools.record_len = 16;
    harness.state_mut().dock.tab = DockTab::Columns;
    steps(&mut harness, 3);
    let (_, _, profiles, fields) = harness.state().bench.tools.columns.clone().expect("profiled");
    assert_eq!(profiles.len(), 16);
    assert!(fields.iter().any(|f| f.start == 4 && f.kind.starts_with("counter")), "{fields:?}");
    harness.get_by_label("Apply as template").click();
    steps(&mut harness, 3);
    let applied = harness.state().bench.template_result.clone().expect("template from columns");
    assert_eq!(applied.records.len(), 256, "{:?}", applied.warnings);
    std::fs::remove_file(path).ok();
    std::fs::remove_file(records_path).ok();
}

#[test]
fn columns_start_from_the_record_width_the_period_scan_published() {
    let mut records = Vec::new();
    for i in 0..512u32 {
        records.extend_from_slice(b"REC:");
        records.extend_from_slice(&i.to_le_bytes());
        records.extend_from_slice(&xorshift_bytes(16, i + 1));
    }
    let path = temp_path("records24.bin");
    std::fs::write(&path, &records).unwrap();
    let mut harness = harness_for(path.clone());
    harness.state_mut().start_period_scan();
    wait_for(&mut harness, |app| !app.scan_pending);
    steps(&mut harness, 2);
    let published = harness.state().bus.latest::<theviewer::bus::topics::RecordWidthEstimated>("doc-1").map(|(fact, estimate)| (fact.producer().to_string(), estimate.width));
    assert_eq!(published, Some(("tool:period-scan".to_string(), 24)));

    harness.state_mut().dock.toggle(DockTab::Columns);
    steps(&mut harness, 3);
    assert_eq!(harness.state().bench.tools.record_len, 24, "Columns reads the width from the bus");
    assert!(harness.query_by_label("Use detected 24 B").is_some());
    std::fs::remove_file(path).ok();
}

#[test]
fn statistics_strings_and_xor_tabs_diagnose_data() {
    let text = "The configuration server is at http://10.0.0.7/api and the log path is /var/log/device.log. ".repeat(40);
    let key = b"K3Y!";
    let mut bytes = text.as_bytes().to_vec();
    let secret_at = bytes.len();
    let secret: Vec<u8> = text.as_bytes().iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect();
    bytes.extend_from_slice(&secret);
    bytes.extend(xorshift_bytes(32 * 1024, 5));
    let path = temp_path("diagnose.bin");
    std::fs::write(&path, &bytes).unwrap();
    let mut harness = harness_for(path.clone());
    harness.state_mut().dock.open = true;

    // Statistics on the noise tail say "random".
    let tail = bytes.len() - 32 * 1024;
    harness.state_mut().anchor = Some(tail);
    harness.state_mut().cursor = bytes.len();
    harness.state_mut().dock.tab = DockTab::Statistics;
    theviewer::analysis_stats::start_statistics(harness.state_mut());
    wait_for(&mut harness, |app| app.bench.tools.stats.result.is_some());
    steps(&mut harness, 3);
    let result = harness.state().bench.tools.stats.result.as_ref().unwrap();
    assert!(result.stats.entropy > 7.9, "{}", result.stats.entropy);
    assert_eq!(result.verdict.label, "Encrypted or random");

    // Strings in the plain text, tagged.
    harness.state_mut().anchor = None;
    harness.state_mut().dock.tab = DockTab::Strings;
    steps(&mut harness, 2);
    harness.get_by_label_contains("Find strings").click();
    wait_for(&mut harness, |app| app.bench.tools.stats.strings.is_some());
    steps(&mut harness, 3);
    let (_, found) = harness.state().bench.tools.stats.strings.clone().unwrap();
    assert!(found.iter().any(|s| s.text.contains("http://10.0.0.7/api")), "{} strings", found.len());

    // XOR: the encrypted copy's key is recovered and applied as an edit.
    harness.state_mut().anchor = Some(secret_at);
    harness.state_mut().cursor = secret_at + secret.len();
    harness.state_mut().dock.tab = DockTab::Xor;
    steps(&mut harness, 2);
    harness.get_by_label_contains("Find XOR keys").click();
    steps(&mut harness, 3);
    let (_, _, candidates, _) = harness.state().bench.tools.stats.xor_candidates.clone().unwrap();
    assert_eq!(candidates.first().map(|c| c.key.clone()), Some(key.to_vec()), "{:?}", candidates.iter().map(|c| &c.key).collect::<Vec<_>>());
    harness.get_all_by_label("Apply").next().unwrap().click();
    steps(&mut harness, 3);
    assert_eq!(harness.state_mut().document.read_range(secret_at, 24), text.as_bytes()[..24].to_vec());
    harness.key_press_modifiers(Modifiers::COMMAND, Key::Z);
    steps(&mut harness, 2);
    assert_eq!(harness.state_mut().document.read_range(secret_at, 24), secret[..24].to_vec(), "undo restores the ciphertext");

    // The plot window's spectrum view renders.
    harness.state_mut().open_plot();
    harness.state_mut().plot.kind = theviewer::plot::PlotKind::Spectrum;
    steps(&mut harness, 3);
    std::fs::remove_file(path).ok();
}

#[test]
fn panels_can_be_rearranged_closed_and_reopened() {
    use theviewer::layout::Pane;
    use theviewer::layouts::Recommended;
    let path = temp_path("layout.bin");
    std::fs::write(&path, xorshift_bytes(64 * 1024, 3)).unwrap();
    let mut harness = harness_for(path.clone());

    for recommended in Recommended::ALL {
        harness.state_mut().apply_recommended(recommended);
        steps(&mut harness, 3);
        assert!(harness.state().raster_rect.is_some(), "{recommended:?} shows the view");
    }

    // The overview: the view takes the left, the hex sits to its right.
    harness.state_mut().apply_recommended(Recommended::Overview);
    harness.state_mut().show_panel(Pane::Tool(DockTab::Statistics));
    steps(&mut harness, 3);
    let raster = harness.state().raster_rect.unwrap();
    let hex = harness.state().hex_body_rect.unwrap();
    assert!(hex.min.x >= raster.max.x - 1.0, "hex {hex:?} is right of the view {raster:?}");

    // Close the hex pane and reopen it from the Panels menu logic.
    harness.state_mut().close_panel(Pane::HexDump);
    steps(&mut harness, 2);
    assert!(!harness.state().panel_is_open(Pane::HexDump));
    harness.state_mut().show_panel(Pane::HexDump);
    steps(&mut harness, 3);
    assert!(harness.state().panel_is_open(Pane::HexDump));

    // The view itself cannot be closed.
    harness.state_mut().close_panel(Pane::Raster);
    assert!(harness.state().panel_is_open(Pane::Raster));

    // A closed tool comes back when a menu asks for it.
    harness.state_mut().close_panel(Pane::Tool(DockTab::Xor));
    harness.state_mut().dock.toggle(DockTab::Xor);
    steps(&mut harness, 3);
    assert!(harness.state().panel_is_open(Pane::Tool(DockTab::Xor)));

    // Detect width opens the period chart pane.
    harness.state_mut().start_period_scan();
    steps(&mut harness, 3);
    assert!(harness.state().panel_is_open(Pane::PeriodChart));
    std::fs::remove_file(path).ok();
}

#[test]
fn crowded_tab_bars_wrap_into_rows_instead_of_scrolling() {
    use theviewer::layouts::Recommended;
    const ROW_HEIGHT: f32 = 26.0;
    let path = temp_path("wrap.bin");
    std::fs::write(&path, xorshift_bytes(16 * 1024, 5)).unwrap();
    let mut harness = harness_for(path.clone());
    // Every tool open: more tabs than one row of the overview's tools pane holds.
    harness.state_mut().apply_recommended(Recommended::Overview);
    for tab in DockTab::ALL {
        harness.state_mut().show_panel(theviewer::layout::Pane::Tool(tab));
        harness.step();
    }
    steps(&mut harness, 4);

    let tab_bar_heights: Vec<(usize, f32)> = harness
        .state()
        .layout
        .iter_leaves()
        .map(|(_, leaf)| (leaf.tabs.len(), leaf.viewport.min.y - leaf.rect.min.y))
        .collect();
    let (most_tabs, crowded_height) = tab_bar_heights
        .iter()
        .copied()
        .max_by_key(|(tabs, _)| *tabs)
        .unwrap();
    assert!(most_tabs >= 8, "the overview stacks its tools: {tab_bar_heights:?}");
    assert!(
        crowded_height >= 2.0 * ROW_HEIGHT - 1.0,
        "{most_tabs} tabs should need more than one row: {tab_bar_heights:?}"
    );
    for (tabs, height) in &tab_bar_heights {
        if *tabs == 1 {
            assert!(*height < ROW_HEIGHT + 1.0, "a single tab keeps a single row: {height}");
        }
    }
    std::fs::remove_file(path).ok();
}

#[test]
fn opening_another_file_stops_watching_the_previous_one() {
    let watched = temp_path("watched.log");
    let other = temp_path("other.bin");
    std::fs::write(&watched, b"first line\n").unwrap();
    std::fs::write(&other, b"other file").unwrap();
    let mut harness = harness_for(watched.clone());
    harness.state_mut().set_watch(true);
    assert!(harness.state().bench.watch_enabled);

    harness.state_mut().load_path(&other);
    assert!(!harness.state().bench.watch_enabled, "watching ends with the file it watched");
    std::fs::OpenOptions::new().append(true).open(&watched).unwrap().write_all(b"second line\n").unwrap();
    let deadline = Instant::now() + Duration::from_millis(800);
    while Instant::now() < deadline {
        steps(&mut harness, 1);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(harness.state_mut().document.read_range(0, 64), b"other file", "the newly opened file is untouched");
    assert!(!harness.state().patterns_in(0, 64).any(|f| f.id == "changed"));
    std::fs::remove_file(watched).ok();
    std::fs::remove_file(other).ok();
}

#[test]
fn file_dialog_answers_open_compare_and_save_without_blocking() {
    use theviewer::app::FileAction;
    use theviewer::dialogs::{Answer, FileRequest};
    let first = temp_path("dialog-first.bin");
    let second = temp_path("dialog-second.bin");
    let saved = temp_path("dialog-saved.bin");
    std::fs::write(&first, b"first file").unwrap();
    std::fs::write(&second, b"second file, longer").unwrap();
    let mut harness = harness_for(first.clone());

    // Opening: the chosen file loads on the next frame.
    harness.state_mut().file_request = Some((FileRequest::answered(Answer::Chosen(second.clone())), FileAction::Open));
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), 19);
    assert!(harness.state().file_request.is_none(), "the answered request is cleared");

    // Cancelling does nothing.
    harness.state_mut().file_request = Some((FileRequest::answered(Answer::Cancelled), FileAction::Open));
    steps(&mut harness, 2);
    assert_eq!(harness.state().document.len(), 19);

    // Comparing starts a diff against the chosen file.
    harness.state_mut().file_request = Some((FileRequest::answered(Answer::Chosen(first.clone())), FileAction::Compare));
    wait_for(&mut harness, |app| app.bench.analysis.diff.is_some());
    assert!(harness.state().bench.analysis.diff.is_some(), "the comparison finished");

    // Saving bytes writes them.
    let bytes = std::sync::Arc::new(b"node bytes".to_vec());
    let action = FileAction::SaveBytes { name: "node".into(), bytes };
    harness.state_mut().file_request = Some((FileRequest::answered(Answer::Chosen(saved.clone())), action));
    steps(&mut harness, 2);
    assert_eq!(std::fs::read(&saved).unwrap(), b"node bytes");
    for path in [first, second, saved] {
        std::fs::remove_file(path).ok();
    }
}

#[test]
fn ask_can_map_the_file_measure_ranges_and_look_for_code() {
    let (bytes, gzip_at, _, _) = composite_file();
    let path = temp_path("ask-tools.bin");
    std::fs::write(&path, &bytes).unwrap();
    let mut harness = harness_for(path.clone());
    let app = harness.state_mut();

    let overview = ask_tool(app, "analysis_overview", serde_json::json!({}));
    assert!(overview.to_string().contains("gzip"), "{overview}");

    let statistics = ask_tool(app, "analysis_statistics", serde_json::json!({ "start": gzip_at, "len": 256 }));
    assert!(statistics["entropy"].as_f64().unwrap() > 0.0, "{statistics}");

    let processor = ask_tool(app, "analysis_processor", serde_json::json!({ "start": 0, "len": 4096 }));
    assert!(!processor["summary"].as_str().unwrap().is_empty());
    let missing = run_ask_tool(app, "analysis_statistics", serde_json::json!({ "len": "all" }));
    assert!(missing.unwrap_err().contains("invalid_params"), "arguments of the wrong type are rejected");

    let segments = ask_tool(app, "analysis_segments", serde_json::json!({}));
    assert_eq!(segments["types"][0]["id"], 0, "{segments}");
    let compressibility = ask_tool(app, "analysis_compressibility", serde_json::json!({ "start": gzip_at, "len": 256 }));
    assert!(!compressibility["ratios"].as_array().unwrap().is_empty());
    let encoding = ask_tool(app, "analysis_text_encoding", serde_json::json!({ "start": 0, "len": 256 }));
    assert!(encoding["encodings"].is_array());
    std::fs::remove_file(path).ok();
}

/// An Ethernet frame carrying UDP from 10.0.0.2:`source_port` to 10.0.0.1:`destination_port`.
fn ethernet_udp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let builder = etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]).ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(source_port, destination_port);
    let mut frame = Vec::new();
    builder.write(&mut frame, payload).unwrap();
    frame
}

/// A little-endian microsecond pcap of Ethernet frames, one second apart.
fn pcap_of(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut file = Vec::new();
    for word in [0xA1B2_C3D4u32, 0x0004_0002, 0, 0, 65_535, 1] {
        file.extend_from_slice(&word.to_le_bytes());
    }
    for (index, frame) in frames.iter().enumerate() {
        for word in [1_700_000_000 + index as u32, 0, frame.len() as u32, frame.len() as u32] {
            file.extend_from_slice(&word.to_le_bytes());
        }
        file.extend_from_slice(frame);
    }
    file
}

#[test]
fn the_packet_viewer_finds_an_embedded_capture_filters_it_and_selects_a_packet_in_the_document() {
    let dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let frames = vec![ethernet_udp(4000, 53, dns_query), ethernet_udp(4001, 9999, b"telemetry one"), ethernet_udp(4002, 9999, b"telemetry two")];
    let mut document = xorshift_bytes(3000, 5);
    let capture_at = document.len();
    document.extend_from_slice(&pcap_of(&frames));
    document.extend(xorshift_bytes(500, 6));
    let path = temp_path("embedded-capture.bin");
    std::fs::write(&path, &document).unwrap();
    // The network layout gives the packet list the view's large pane.
    let launch = Launch { path: Some(path.clone()), layout: Some("network".to_string()), ..Default::default() };
    let mut harness = Harness::builder().with_size(egui::vec2(1500.0, 1000.0)).build_eframe(move |creation| {
        theviewer::theme::apply(&creation.egui_ctx);
        ViewerApp::new(launch)
    });
    steps(&mut harness, 3);

    harness.state_mut().dock.toggle(DockTab::Packets);
    steps(&mut harness, 3);
    harness.get_by_label("Find captures").click();
    // The click starts a background search on the next frame, so wait for its
    // result to be listed rather than for the panel to be idle.
    let capture_label = format!("pcap at {capture_at:#x}");
    let started = Instant::now();
    while harness.query_by_label_contains(&capture_label).is_none() && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
        harness.step();
    }
    steps(&mut harness, 2);
    harness.get_by_label_contains(&format!("pcap at {capture_at:#x}")).scroll_to_me();
    steps(&mut harness, 2);
    harness.get_by_label_contains(&format!("pcap at {capture_at:#x}")).click();
    wait_for(&mut harness, |app| app.bench.panels.packets.rows().len() == 3 && !app.bench.panels.packets.is_busy());
    steps(&mut harness, 2);
    let rows = harness.state().bench.panels.packets.rows();
    assert_eq!(rows[0].summary.protocol, "DNS");
    assert_eq!(rows[0].summary.info, "Standard query 0x1234 A example.com");

    harness.state_mut().bench.panels.packets.set_filter("udp port:9999");
    steps(&mut harness, 3);
    assert_eq!(harness.state().bench.panels.packets.visible_rows(), &[1, 2]);
    assert!(harness.query_by_label_contains("2 of 3 shown").is_some());

    harness.get_by_label_contains("4002 → 9999").scroll_to_me();
    steps(&mut harness, 2);
    harness.get_by_label_contains("4002 → 9999").click_accesskit();
    steps(&mut harness, 3);
    let app = harness.state();
    let packet = app.bench.panels.packets.packet_set().unwrap().packets[2].clone();
    assert_eq!(app.selection(), Some((packet.offset, packet.len)), "the packet's bytes are selected in the document");
    assert_eq!(&document[packet.offset..packet.end()], frames[2].as_slice());

    // Cmd-clicking a second packet selects both packets' bytes as two ranges.
    harness.get_by_label_contains("4001 → 9999").scroll_to_me();
    steps(&mut harness, 2);
    harness.event(egui::Event::ModifiersChanged(egui::Modifiers::COMMAND));
    harness.get_by_label_contains("4001 → 9999").click_accesskit();
    harness.step();
    harness.event(egui::Event::ModifiersChanged(egui::Modifiers::NONE));
    steps(&mut harness, 3);
    let app = harness.state();
    let packets = &app.bench.panels.packets.packet_set().unwrap().packets;
    assert_eq!(app.bench.panels.packets.selected_packets(), vec![1, 2]);
    assert_eq!(app.selection_ranges(), vec![(packets[1].offset, packets[1].len), (packets[2].offset, packets[2].len)]);
    std::fs::remove_file(path).ok();
}

/// Step until a label containing `text` is shown, or ten seconds pass.
fn wait_for_label(harness: &mut Harness<'static, ViewerApp>, text: &str) {
    let started = Instant::now();
    while harness.query_by_label_contains(text).is_none() && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
        harness.step();
    }
}

#[test]
fn the_reference_tab_explains_the_udp_header_under_the_cursor() {
    let path = temp_path("reference-udp.pcap");
    std::fs::write(&path, pcap_of(&[ethernet_udp(4000, 9999, b"telemetry one")])).unwrap();
    let mut harness = harness_for(path.clone());
    wait_for(&mut harness, |app| app.patterns.iter().any(|finding| finding.id == "pcap"));

    // File header, record header, Ethernet and IPv4, then the UDP header,
    // whose destination port is its second field.
    let udp_at = 24 + 16 + 14 + 20;
    harness.state_mut().set_cursor(udp_at + 2, false);
    harness.state_mut().dock.toggle(DockTab::Reference);
    wait_for_label(&mut harness, "Destination port");
    steps(&mut harness, 2);
    let reference = &harness.state().bench.panels.reference;
    let labels: Vec<&str> = reference.stack().iter().map(|entry| entry.label.as_str()).collect();
    // Capture, Ethernet, IPv4 and UDP; the middle two are named by whatever
    // notes exist for them.
    assert_eq!(labels.len(), 4, "{labels:?}");
    assert_eq!((labels[0], labels[3]), ("pcap capture", "UDP"), "outermost first: {labels:?}");
    let chosen = reference.chosen_entry().expect("a format is shown");
    assert_eq!((chosen.label.as_str(), chosen.start, chosen.len), ("UDP", udp_at, 8));
    assert!(harness.query_all_by_label("User Datagram Protocol").next().is_some(), "the notes' name is the heading");
    let udp = theviewer::reference::lookup("udp").unwrap();
    if let Some(note) = udp.field("Destination port") {
        assert!(harness.query_all_by_label(&note.meaning).next().is_some(), "the field's meaning is listed");
    }

    // Pointing at a field's row outlines its bytes; clicking selects them.
    // Scrolling the row into view is animated: let it settle first.
    harness.get_by_label("Destination port").scroll_to_me();
    steps(&mut harness, 10);
    harness.get_by_label("Destination port").hover();
    steps(&mut harness, 3);
    assert_eq!(harness.state().pointed_bytes(), Some((udp_at + 2, 2)));
    harness.get_by_label("Destination port").click();
    steps(&mut harness, 3);
    assert_eq!(harness.state().selection(), Some((udp_at + 2, 2)));
    let chosen = harness.state().bench.panels.reference.chosen_entry().map(|entry| entry.label.clone());
    assert_eq!(chosen.as_deref(), Some("UDP"), "the tab stays on the format the field belongs to");
    std::fs::remove_file(path).ok();
}

#[test]
fn the_reference_tab_names_an_undissected_payload_by_its_port() {
    // SSH is not dissected, so an encrypted SSH packet's payload is plain
    // bytes; port 22 still says what they probably are.
    let builder = etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]).ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).tcp(50_000, 22, 1000, 4096);
    let mut frame = Vec::new();
    builder.write(&mut frame, &xorshift_bytes(48, 7)).unwrap();
    let path = temp_path("reference-guess.pcap");
    std::fs::write(&path, pcap_of(&[frame])).unwrap();
    let mut harness = harness_for(path.clone());
    wait_for(&mut harness, |app| app.patterns.iter().any(|finding| finding.id == "pcap"));

    let payload_at = 24 + 16 + 14 + 20 + 20;
    harness.state_mut().set_cursor(payload_at + 4, false);
    harness.state_mut().dock.toggle(DockTab::Reference);
    wait_for_label(&mut harness, "Not dissected; the notes describe what this port usually carries.");
    let reference = &harness.state().bench.panels.reference;
    let chosen = reference.chosen_entry().expect("the guess is shown");
    let ssh = theviewer::reference::lookup("ssh-banner").unwrap();
    assert_eq!(chosen.label, format!("{}?", ssh.short_name()));
    assert_eq!((chosen.start, chosen.len), (payload_at, 48), "the guess covers the payload");
    assert_eq!(chosen.guess.as_ref().map(|guess| guess.reason.as_str()), Some("TCP port 22 is registered to it"));
    assert!(harness.query_by_label(&ssh.name).is_some(), "the notes' name is the heading");
    std::fs::remove_file(path).ok();
}

#[test]
fn picking_a_layer_in_the_packet_viewer_turns_the_reference_tab_to_that_protocol() {
    let dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let path = temp_path("reference-follow.pcap");
    std::fs::write(&path, pcap_of(&[ethernet_udp(4000, 53, dns_query)])).unwrap();
    let mut harness = harness_for(path.clone());
    theviewer::panel_packets::open_capture_at(harness.state_mut(), 0);
    wait_for(&mut harness, |app| app.bench.panels.packets.rows().len() == 1 && !app.bench.panels.packets.is_busy());

    // The cursor in the DNS message, with the Reference tab beside the packets.
    let dns_at = 24 + 16 + 14 + 20 + 8;
    harness.state_mut().set_cursor(dns_at + 4, false);
    harness.state_mut().dock.toggle(DockTab::Reference);
    steps(&mut harness, 3);
    harness.state_mut().dock.toggle(DockTab::Packets);
    let ipv4_title = "Internet Protocol version 4 · 20 bytes at +14";
    wait_for_label(&mut harness, ipv4_title);
    assert!(harness.state().bench.panels.reference.stack().len() >= 4, "capture, Ethernet, IPv4, UDP and DNS are stacked");

    harness.get_by_label(ipv4_title).scroll_to_me();
    steps(&mut harness, 10);
    harness.get_by_label(ipv4_title).click_accesskit();
    steps(&mut harness, 4);
    let ipv4_at = 24 + 16 + 14;
    assert_eq!(harness.state().selection(), Some((ipv4_at, 20)), "the layer's bytes are selected");
    let chosen = harness.state().bench.panels.reference.chosen_entry().map(|entry| (entry.key.clone(), entry.start));
    assert_eq!(chosen, Some(("Internet Protocol version 4".to_string(), ipv4_at)));
    std::fs::remove_file(path).ok();
}

#[test]
fn opening_a_capture_offers_the_network_layout_and_switching_lists_its_packets_in_front() {
    use theviewer::layout::Pane;
    use theviewer::layouts::Recommended;
    let dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let path = temp_path("offer.pcap");
    std::fs::write(&path, pcap_of(&[ethernet_udp(4000, 53, dns_query)])).unwrap();
    let mut harness = harness_for(path.clone());
    assert_eq!(harness.state().layouts.suggestion, Some(Recommended::Network));
    harness.get_by_label("Suits the Network capture layout").hover();
    harness.get_by_label("Switch").click();
    wait_for(&mut harness, |app| app.layouts.suggestion.is_none());
    let app = harness.state();
    assert_eq!(app.layouts.current.as_deref(), Some("Network capture"));
    let front: Vec<Pane> = app.layout.iter_leaves().filter_map(|(_, leaf)| leaf.tabs.get(leaf.active.0).copied()).collect();
    assert!(front.contains(&Pane::Tool(DockTab::Packets)), "{front:?}");
    // The packets are listed straight away rather than waiting for "Find captures".
    wait_for(&mut harness, |app| app.bench.panels.packets.rows().len() == 1 && !app.bench.panels.packets.is_busy());
    assert_eq!(harness.state().bench.panels.packets.rows()[0].summary.protocol, "DNS");

    // A file with nothing to suggest leaves the status bar alone.
    let plain = temp_path("offer-plain.bin");
    std::fs::write(&plain, xorshift_bytes(4096, 9)).unwrap();
    harness.state_mut().load_path(&plain);
    assert_eq!(harness.state().layouts.suggestion, None);
    std::fs::remove_file(path).ok();
    std::fs::remove_file(plain).ok();
}

/// A NetBIOS name service node status query for "*", from port 137 to
/// port 137, built byte by byte: a protocol tshark decodes and we do not.
fn nbns_query_frame() -> Vec<u8> {
    let mut nbns = vec![0x12, 0x34, 0x00, 0x10]; // transaction ID; a broadcast query
    nbns.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // one question
    nbns.push(32);
    nbns.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // "*" padded with zeros
    nbns.extend_from_slice(&[0, 0, 0x21, 0, 1]); // end of name, NBSTAT, class IN
    let builder = etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [0xFF; 6]).ipv4([10, 0, 0, 2], [10, 0, 0, 255], 64).udp(137, 137);
    let mut frame = Vec::new();
    builder.write(&mut frame, &nbns).unwrap();
    frame
}

#[test]
fn decoding_with_tshark_adds_an_nbns_layer_whose_fields_select_their_bytes() {
    if theviewer::packets::tshark::find_tshark(None).is_none() {
        eprintln!("tshark is not installed; skipping the tshark decoding test");
        return;
    }
    let path = temp_path("tshark-nbns.pcap");
    std::fs::write(&path, pcap_of(&[nbns_query_frame()])).unwrap();
    let mut harness = harness_for(path.clone());
    theviewer::panel_packets::open_capture_at(harness.state_mut(), 0);
    wait_for(&mut harness, |app| app.bench.panels.packets.rows().len() == 1 && !app.bench.panels.packets.is_busy());
    assert_eq!(harness.state().bench.panels.packets.rows()[0].summary.protocol, "UDP", "our own dissector stops at UDP");

    wait_for_label(&mut harness, "Decode with tshark");
    harness.get_by_label("Decode with tshark").click();
    wait_for(&mut harness, |app| app.bench.panels.packets.rows()[0].summary.protocol == "NBNS" && !app.bench.panels.packets.is_busy());
    assert_eq!(harness.state().bench.panels.packets.rows()[0].summary.protocol, "NBNS");
    harness.state_mut().bench.panels.packets.set_filter("proto:nbns");
    steps(&mut harness, 3);
    assert_eq!(harness.state().bench.panels.packets.visible_rows(), &[0], "tshark's protocols can be filtered on");

    harness.get_by_label_contains("NetBIOS Name Service").scroll_to_me();
    steps(&mut harness, 2);
    harness.get_by_label_contains("NetBIOS Name Service").click_accesskit();
    wait_for_label(&mut harness, "Transaction ID:");
    assert!(harness.query_by_label("tshark").is_some(), "the layer tshark decoded is tagged");
    harness.get_by_label("Transaction ID:").scroll_to_me();
    steps(&mut harness, 10);
    harness.get_by_label("Transaction ID:").click_accesskit();
    steps(&mut harness, 3);
    // File header, record header, Ethernet, IPv4 and UDP, then the first bytes.
    let transaction_id_at = 24 + 16 + 14 + 20 + 8;
    assert_eq!(harness.state().selection(), Some((transaction_id_at, 2)));
    std::fs::remove_file(path).ok();
}

#[test]
fn the_packet_list_filters_by_wireshark_field_names() {
    let dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let frames = vec![ethernet_udp(4000, 53, dns_query), ethernet_udp(4001, 9999, b"telemetry one"), ethernet_udp(4002, 9999, b"telemetry two")];
    let path = temp_path("wireshark-filter.pcap");
    std::fs::write(&path, pcap_of(&frames)).unwrap();
    let mut harness = harness_for(path.clone());
    // The network layout shows the packets, which loads the capture.
    harness.state_mut().apply_recommended(theviewer::layouts::Recommended::Network);
    wait_for(&mut harness, |app| app.bench.panels.packets.rows().len() == 3 && !app.bench.panels.packets.is_busy());

    for (filter, shown) in [("udp.dstport==53", 1), ("udp.dstport>1000", 2), ("udp.srcport!=4001", 2), ("udp.dstport", 3), ("ip.ttl==1", 0)] {
        harness.state_mut().bench.panels.packets.set_filter(filter);
        steps(&mut harness, 3);
        let packets = &harness.state().bench.panels.packets;
        assert_eq!(packets.visible_rows().len(), shown, "{filter}");
    }
    std::fs::remove_file(path).ok();
}

/// A DNS query for `name` with transaction ID `id`, after its two-byte
/// length, as DNS travels over TCP.
fn length_prefixed_dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut message = id.to_be_bytes().to_vec();
    message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.extend_from_slice(&[0, 0, 1, 0, 1]);
    [(message.len() as u16).to_be_bytes().to_vec(), message].concat()
}

#[test]
fn frames_split_by_their_length_field_are_listed_as_the_dns_messages_they_are() {
    let names = ["www.example.com", "mail.example.org", "printer.local", "api.example.net"];
    let file: Vec<u8> = names.iter().enumerate().flat_map(|(index, name)| length_prefixed_dns_query(0x100 + index as u16, name)).collect();
    let path = temp_path("dns-messages.bin");
    std::fs::write(&path, &file).unwrap();
    let mut harness = harness_for(path.clone());
    harness.state_mut().dock.toggle(DockTab::Packets);
    steps(&mut harness, 2);
    // The default rule is a big-endian u16 at the start counting what follows.
    let split = &mut harness.state_mut().bench.panels.packets.grid.split;
    split.rule = theviewer::panel_packets_grid::SplitRule::LengthField;
    split.whole_document = true;
    harness.get_by_label("Split into frames").click();
    steps(&mut harness, 2);
    harness.get_by_label("Split").click();
    wait_for(&mut harness, |app| app.bench.panels.packets.rows().len() == 4 && !app.bench.panels.packets.is_busy());
    wait_for_label(&mut harness, "decoded as DNS with a length prefix (detected, 4 of 4 sampled)");
    assert!(harness.query_by_label_contains("decoded as DNS with a length prefix (detected, 4 of 4 sampled)").is_some());

    let rows = harness.state().bench.panels.packets.rows();
    assert!(rows.iter().all(|row| row.summary.protocol == "DNS"), "{rows:?}");
    assert_eq!(rows[0].summary.info, "Standard query 0x0100 A www.example.com");
    wait_for_label(&mut harness, "Standard query 0x0101 A mail.example.org");
    assert!(harness.query_by_label_contains("Standard query 0x0101 A mail.example.org").is_some());

    harness.state_mut().bench.panels.packets.set_filter("dns.qry.name~example");
    steps(&mut harness, 3);
    assert_eq!(harness.state().bench.panels.packets.visible_rows(), &[0, 1, 3]);
    harness.state_mut().bench.panels.packets.set_filter("dns");
    steps(&mut harness, 3);
    assert_eq!(harness.state().bench.panels.packets.visible_rows().len(), 4);
    std::fs::remove_file(path).ok();
}
