//! theviewer: a fast binary viewer that rasters any file as pixels and lets
//! you reshape and edit the underlying bytes.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use eframe::egui;

use theviewer::app::{self, Launch};
use theviewer::logo;
use theviewer::ops;
use theviewer::raster::{Palette, PixelFormat};
use theviewer::theme;

/// Pixel size of the window and Dock icon.
const ICON_SIZE: u32 = 512;

const USAGE: &str = "\
usage: theviewer [FILE] [--format NAME] [--palette NAME] [--width PIXELS] [--offset BYTES] [--cursor BYTES] [--zoom FACTOR] [--detect] [--open] [--tool NAME] [--layout NAME]

  --format   one of: bit1 bit1lsb nibble4 gray8 class rgb565 gray16le gray16be rgb8 bgr8 rgba8 bgra8
  --palette  one of: grey viridis inferno ocean amber (single-channel formats)
  --width    pixels per row (default 512)
  --offset   byte offset of the first pixel (decimal or 0x hex)
  --cursor   initial cursor offset (decimal or 0x hex)
  --zoom     pixel scale, e.g. 2 or 0.5
  --detect   scan for repeating periods on startup and open the structure panel
  --open     open the image, audio or video at the cursor
  --layout   start with a panel layout: default right left focus
  --tool     open the tools dock on a tab: report ask template columns protocol statistics strings xor checksums disassembly unpacked diff live
";

fn parse_launch() -> Result<Launch, String> {
    let mut launch = Launch::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value_for = |flag: &str| args.next().ok_or_else(|| format!("{flag} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Err(USAGE.to_string()),
            "--detect" => launch.detect = true,
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
    Ok(launch)
}

fn main() -> eframe::Result {
    let launch = match parse_launch() {
        Ok(launch) => Launch { restore_layout: true, ..launch },
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
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
