//! Writes the logo as a PNG: `cargo run --bin render_logo -- assets/logo.png [size]`.

use theviewer::logo;

/// Size used when none is given, large enough for a README or an app bundle.
const DEFAULT_SIZE: u32 = 512;

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("usage: render_logo OUTPUT.png [SIZE]")?;
    let size = match args.next() {
        Some(text) => text.parse().map_err(|_| format!("bad size '{text}'"))?,
        None => DEFAULT_SIZE,
    };
    let rgba = logo::render_rgba(size);
    image::save_buffer(&path, &rgba, size, size, image::ExtendedColorType::Rgba8).map_err(|e| format!("{path}: {e}"))?;
    println!("Wrote {path} ({size}×{size})");
    Ok(())
}
