//! theviewer: a fast binary viewer that rasters any file as pixels and lets
//! you reshape and edit the underlying bytes.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eframe::egui;

use theviewer::api::{self, ApiError, HeadlessWorkspace, Workspace};
use theviewer::app::{self, Launch};
use theviewer::headless;
use theviewer::logo;
use theviewer::mcp;
use theviewer::ops;
use theviewer::raster::{Palette, PixelFormat};
use theviewer::theme;

/// Pixel size of the window and Dock icon.
const ICON_SIZE: u32 = 512;
/// Exit code for a command line that could not be understood.
const EXIT_USAGE: i32 = 2;
/// Exit code for a headless report that could not be produced.
const EXIT_FAILURE: i32 = 1;

const USAGE: &str = "\
usage: theviewer [FILE] [--format NAME] [--palette NAME] [--width PIXELS] [--offset BYTES] [--cursor BYTES] [--zoom FACTOR] [--detect] [--open] [--tool NAME] [--layout NAME]
       theviewer FILE --report | --json
       theviewer api METHOD ['{JSON PARAMS}'] [FILE]
       theviewer api --describe
       theviewer mcp [--plugins DIR]... [FILE...]

  --report   print a plain-text report of FILE without opening a window
  --json     print the same report as JSON, for scripts and CI
  api        run one data API method on FILE without opening a window and print its JSON
             result; --describe prints every method with its schemas (see docs/api.md)
  mcp        serve the files over the Model Context Protocol on standard input and output,
             for Claude Code and other MCP clients; --plugins loads plugins from DIR instead
             of ./plugins and ~/.config/theviewer/plugins

  --format   one of: bit1 bit1lsb nibble4 gray8 class rgb565 gray16le gray16be rgb8 bgr8 rgba8 bgra8
             or a numeric heatmap: u16le u16be i16le i16be u32le u32be i32le i32be f32le f32be
  --palette  one of: grey viridis inferno ocean amber diverging (single-channel formats)
  --width    pixels per row (default 512)
  --offset   byte offset of the first pixel (decimal or 0x hex)
  --cursor   initial cursor offset (decimal or 0x hex)
  --zoom     pixel scale, e.g. 2 or 0.5
  --detect   scan for repeating periods on startup and open the structure panel
  --open     open the image, audio or video at the cursor
  --layout   start with a layout for this session (the last session's is kept): overview network
             structure firmware signals forensics compare focus, or the name of one you saved
  --tool     open the tools dock on a tab: report reference structure-map size-map ask dot-plot trigrams images template columns protocol packets bits statistics characterise strings xor crypto checksums learn disassembly firmware unpacked forensics diff compare live
";

/// How to print a report without opening a window.
#[derive(Clone, Copy)]
enum HeadlessOutput {
    Text,
    Json,
}

/// The window's start-up settings, and the headless report to print instead
/// of opening one, if asked for.
fn parse_launch() -> Result<(Launch, Option<HeadlessOutput>), String> {
    let mut launch = Launch::default();
    let mut headless = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value_for = |flag: &str| args.next().ok_or_else(|| format!("{flag} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Err(USAGE.to_string()),
            "--detect" => launch.detect = true,
            "--report" => headless = Some(HeadlessOutput::Text),
            "--json" => headless = Some(HeadlessOutput::Json),
            "--open" => launch.open_media = true,
            "--tool" => launch.tool = Some(value_for("--tool")?),
            "--layout" => launch.layout = Some(value_for("--layout")?),
            "--format" => {
                let name = value_for("--format")?;
                launch.format = Some(
                    PixelFormat::from_short_name(&name).ok_or_else(|| format!("unknown format '{name}'\n\n{USAGE}"))?,
                );
            }
            "--palette" => {
                let name = value_for("--palette")?;
                launch.palette = Some(Palette::from_name(&name).ok_or_else(|| format!("unknown palette '{name}'\n\n{USAGE}"))?);
            }
            "--width" => {
                let text = value_for("--width")?;
                launch.width = Some(text.parse().map_err(|_| format!("bad width '{text}'"))?);
            }
            "--offset" => {
                let text = value_for("--offset")?;
                launch.offset = Some(ops::parse_offset(&text).ok_or_else(|| format!("bad offset '{text}'"))?);
            }
            "--cursor" => {
                let text = value_for("--cursor")?;
                launch.cursor = Some(ops::parse_offset(&text).ok_or_else(|| format!("bad cursor '{text}'"))?);
            }
            "--zoom" => {
                let text = value_for("--zoom")?;
                let zoom: f32 = text.parse().map_err(|_| format!("bad zoom '{text}'"))?;
                if !zoom.is_finite() || zoom <= 0.0 {
                    return Err(format!("bad zoom '{text}': expected a positive number such as 2 or 0.5"));
                }
                launch.zoom = Some(zoom);
            }
            other if other.starts_with('-') => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
            file => launch.path = Some(PathBuf::from(file)),
        }
    }
    Ok((launch, headless))
}

/// Run `theviewer api …` (the arguments after `api`) and return the
/// process exit code. The result is printed as JSON; an error is printed as
/// JSON on stderr, with a non-zero exit code.
fn run_api(args: &[String]) -> i32 {
    let (method, rest) = match args {
        // The methods plugins register are listed with the rest.
        [flag] if flag == "--describe" => ("api.describe", &[][..]),
        [method, rest @ ..] if !method.starts_with('-') => (method.as_str(), rest),
        _ => {
            eprintln!("theviewer api needs a method, or --describe\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let (params, file) = match rest {
        [] => ("{}", None),
        [params] if params.trim_start().starts_with('{') => (params.as_str(), None),
        [file] => ("{}", Some(file)),
        [params, file] => (params.as_str(), Some(file)),
        _ => {
            eprintln!("theviewer api takes a method, its JSON parameters and one file\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    match call_headless(method, params, file.map(Path::new)) {
        Ok(result) => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
            0
        }
        Err(error) => {
            eprintln!("{}", serde_json::to_string_pretty(&error.to_json()).unwrap_or_default());
            EXIT_FAILURE
        }
    }
}

/// Run one API method in a workspace holding just `file`, if given.
fn call_headless(method: &str, params: &str, file: Option<&Path>) -> Result<serde_json::Value, ApiError> {
    let params: serde_json::Value = serde_json::from_str(params).map_err(|error| ApiError::invalid_params(format!("the parameters are not JSON: {error}")))?;
    let (host, _) = app::load_plugin_host();
    let mut workspace = HeadlessWorkspace::new(Arc::new(app::build_registry_with(Some(&host))));
    if let Ok(host) = host.lock() {
        workspace.set_registered_methods(host.methods());
    }
    if let Some(file) = file {
        workspace.open_path(file)?;
    }
    api::call(&mut workspace, &api::Caller::Cli, method, params)
}

/// Run `theviewer mcp …` (the arguments after `mcp`) until the client
/// closes standard input, and return the process exit code.
fn run_mcp(args: &[String]) -> i32 {
    let mut options = mcp::Options::default();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                eprintln!("{USAGE}");
                return EXIT_USAGE;
            }
            "--plugins" => match args.next() {
                Some(dir) => options.plugin_dirs.get_or_insert_with(Vec::new).push(PathBuf::from(dir)),
                None => {
                    eprintln!("--plugins needs a directory\n\n{USAGE}");
                    return EXIT_USAGE;
                }
            },
            other if other.starts_with('-') => {
                eprintln!("unknown option '{other}' for theviewer mcp\n\n{USAGE}");
                return EXIT_USAGE;
            }
            file => options.files.push(PathBuf::from(file)),
        }
    }
    match mcp::run_stdio(&options) {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("theviewer mcp: {message}");
            EXIT_FAILURE
        }
    }
}

/// Print the report for `path` and return the process exit code.
fn run_headless(path: Option<&Path>, output: HeadlessOutput) -> i32 {
    let Some(path) = path else {
        eprintln!("--report and --json need a file to analyse\n\n{USAGE}");
        return EXIT_USAGE;
    };
    let (host, _) = app::load_plugin_host();
    let registry = app::build_registry_with(Some(&host));
    match headless::analyse(path, &registry) {
        Ok(report) => {
            match output {
                HeadlessOutput::Text => print!("{}", headless::render_text(&report)),
                HeadlessOutput::Json => println!("{}", headless::render_json(&report)),
            }
            0
        }
        Err(message) => {
            eprintln!("theviewer: {message}");
            EXIT_FAILURE
        }
    }
}

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|first| first == "api") {
        std::process::exit(run_api(&args[1..]));
    }
    if args.first().is_some_and(|first| first == "mcp") {
        std::process::exit(run_mcp(&args[1..]));
    }
    let launch = match parse_launch() {
        Ok((launch, Some(output))) => std::process::exit(run_headless(launch.path.as_deref(), output)),
        Ok((launch, None)) => Launch { restore_layout: true, ..launch },
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(EXIT_USAGE);
        }
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("theviewer")
            .with_inner_size([1500.0, 950.0])
            .with_drag_and_drop(true)
            .with_icon(egui::IconData { rgba: logo::render_rgba(ICON_SIZE), width: ICON_SIZE, height: ICON_SIZE }),
        ..Default::default()
    };
    eframe::run_native(
        "theviewer",
        options,
        Box::new(move |creation| {
            theme::apply(&creation.egui_ctx);
            creation.egui_ctx.options_mut(|options| options.zoom_with_keyboard = false);
            Ok(Box::new(app::ViewerApp::new(launch)))
        }),
    )
}
