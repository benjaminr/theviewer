//! Media decoding behind the viewer and players: format detection, image
//! and animation decoding, audio analysis, and video via `ffmpeg`.
//!
//! Nothing here touches the UI, so it can be tested headlessly. Images and
//! audio are decoded in pure Rust; video needs `ffmpeg` and `ffprobe` on the
//! `PATH`, and degrades to "open in the system player" without them.

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::Duration;

use symphonia::core::audio::SampleBuffer;
use symphonia::core::codecs::{CODEC_TYPE_NULL, DecoderOptions};
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

/// The broad kind of media, which decides which player opens it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Audio,
    Video,
}

impl MediaKind {
    pub fn verb(self) -> &'static str {
        match self {
            MediaKind::Image => "View image",
            MediaKind::Audio => "Play audio",
            MediaKind::Video => "Play video",
        }
    }
}

/// What the leading bytes look like, with a short format name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaFormat {
    pub kind: MediaKind,
    pub name: &'static str,
}

/// Recognise media by its leading bytes.
pub fn detect(bytes: &[u8]) -> Option<MediaFormat> {
    let format = |kind, name| Some(MediaFormat { kind, name });
    let at = |offset: usize, magic: &[u8]| bytes.get(offset..offset + magic.len()) == Some(magic);

    // Containers that hold either audio or video need a closer look.
    if at(0, b"RIFF") {
        return if at(8, b"WAVE") {
            format(MediaKind::Audio, "WAV")
        } else if at(8, b"AVI ") {
            format(MediaKind::Video, "AVI")
        } else if at(8, b"WEBP") {
            format(MediaKind::Image, "WebP")
        } else {
            None
        };
    }
    if at(4, b"ftyp") {
        let brand = bytes.get(8..12).unwrap_or_default();
        let audio_brands: [&[u8]; 4] = [b"M4A ", b"M4B ", b"M4P ", b"F4A "];
        let image_brands: [&[u8]; 4] = [b"heic", b"heix", b"mif1", b"avif"];
        return if audio_brands.contains(&brand) {
            format(MediaKind::Audio, "M4A")
        } else if image_brands.contains(&brand) {
            // HEIF and AVIF stills; ffmpeg can render them as one frame.
            format(MediaKind::Video, "HEIF/AVIF")
        } else if brand == b"qt  " {
            format(MediaKind::Video, "QuickTime")
        } else {
            format(MediaKind::Video, "MP4")
        };
    }
    if at(0, &[0x1A, 0x45, 0xDF, 0xA3]) {
        let is_webm = bytes.iter().take(64).collect::<Vec<_>>().windows(4).any(|w| w == [&b'w', &b'e', &b'b', &b'm']);
        return format(MediaKind::Video, if is_webm { "WebM" } else { "Matroska" });
    }
    if at(0, b"OggS") {
        let page = bytes.get(..128).unwrap_or(bytes);
        let has = |needle: &[u8]| page.windows(needle.len()).any(|w| w == needle);
        return if has(b"theora") {
            format(MediaKind::Video, "Ogg Theora")
        } else if has(b"OpusHead") {
            format(MediaKind::Audio, "Ogg Opus")
        } else {
            format(MediaKind::Audio, "Ogg Vorbis")
        };
    }
    if at(0, b"FLV\x01") {
        return format(MediaKind::Video, "FLV");
    }
    if is_mpeg_transport_stream(bytes) {
        return format(MediaKind::Video, "MPEG-TS");
    }
    if at(0, b"fLaC") {
        return format(MediaKind::Audio, "FLAC");
    }
    if at(0, b"ID3") {
        return format(MediaKind::Audio, "MP3");
    }
    if at(0, b"FORM") && (at(8, b"AIFF") || at(8, b"AIFC")) {
        return format(MediaKind::Audio, "AIFF");
    }
    if at(0, b"caff") {
        return format(MediaKind::Audio, "CAF");
    }
    if bytes.len() >= 4 && bytes[0] == 0xFF && bytes[1] & 0xF6 == 0xF0 {
        return format(MediaKind::Audio, "AAC (ADTS)");
    }
    if is_mpeg_audio_frame(bytes) {
        return format(MediaKind::Audio, "MP3");
    }
    if let Ok(image_format) = image::guess_format(bytes) {
        return format(MediaKind::Image, image_format_name(image_format));
    }
    None
}

fn image_format_name(format: image::ImageFormat) -> &'static str {
    match format {
        image::ImageFormat::Png => "PNG",
        image::ImageFormat::Jpeg => "JPEG",
        image::ImageFormat::Gif => "GIF",
        image::ImageFormat::Bmp => "BMP",
        image::ImageFormat::WebP => "WebP",
        image::ImageFormat::Tiff => "TIFF",
        image::ImageFormat::Ico => "ICO",
        _ => "image",
    }
}

/// MPEG-TS packets are 188 bytes, each starting with the 0x47 sync byte.
fn is_mpeg_transport_stream(bytes: &[u8]) -> bool {
    const PACKET: usize = 188;
    bytes.len() >= PACKET * 4 && (0..4).all(|k| bytes[k * PACKET] == 0x47)
}

/// An MPEG audio frame header that is followed by another frame where its
/// length says the next one starts.
fn is_mpeg_audio_frame(bytes: &[u8]) -> bool {
    let Some(len) = mpeg_frame_len(bytes) else { return false };
    bytes.get(len..).and_then(mpeg_frame_len).is_some()
}

fn mpeg_frame_len(bytes: &[u8]) -> Option<usize> {
    const BITRATES: [u32; 16] = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0];
    const RATES: [u32; 4] = [44_100, 48_000, 32_000, 0];
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] & 0xFE != 0xFA {
        // MPEG-1 Layer III only; enough to recognise ordinary MP3 data.
        return None;
    }
    let bitrate = BITRATES[(bytes[2] >> 4) as usize] * 1000;
    let rate = RATES[((bytes[2] >> 2) & 3) as usize];
    if bitrate == 0 || rate == 0 {
        return None;
    }
    let padding = ((bytes[2] >> 1) & 1) as u32;
    Some((144 * bitrate / rate + padding) as usize)
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

/// Largest image the viewer decodes, per side.
pub const MAX_IMAGE_SIDE: u32 = 16_384;
/// Most frames kept from an animation.
const MAX_FRAMES: usize = 500;
/// Most memory the decoded pixels of one image (all frames together) may use.
const MAX_DECODED_BYTES: u64 = 1024 * 1024 * 1024;
/// Bytes per decoded RGBA pixel.
const RGBA_BYTES: u64 = 4;

/// A decoded image, possibly animated.
pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    pub frames: Vec<ImageFrame>,
}

pub struct ImageFrame {
    /// Row-major RGBA.
    pub rgba: Vec<u8>,
    pub delay: Duration,
}

/// Decode a still image or every frame of an animated GIF.
pub fn decode_image(bytes: &[u8]) -> Result<DecodedImage, String> {
    use image::AnimationDecoder;

    let format = image::guess_format(bytes).map_err(|e| e.to_string())?;
    if format == image::ImageFormat::Gif {
        use image::ImageDecoder;

        let decoder = image::codecs::gif::GifDecoder::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
        // Every frame is composited onto the full logical screen, so check its
        // size before decoding any: a tiny file can declare a huge screen.
        let (screen_width, screen_height) = decoder.dimensions();
        if screen_width > MAX_IMAGE_SIDE || screen_height > MAX_IMAGE_SIDE {
            return Err(format!("GIF is {screen_width}×{screen_height}; the most the viewer shows is {MAX_IMAGE_SIDE} per side"));
        }
        let frame_bytes = u64::from(screen_width) * u64::from(screen_height) * RGBA_BYTES;
        let frames_that_fit = (MAX_DECODED_BYTES / frame_bytes.max(1)).max(1) as usize;
        let mut frames = Vec::new();
        let (mut width, mut height) = (0, 0);
        for frame in decoder.into_frames().take(MAX_FRAMES.min(frames_that_fit)) {
            let frame = frame.map_err(|e| e.to_string())?;
            let (numerator, denominator) = frame.delay().numer_denom_ms();
            // Browsers treat very short GIF delays as 100 ms; keep at least 20 ms.
            let delay_ms = numerator.checked_div(denominator).map_or(100, |ms| ms.max(20));
            let buffer = frame.into_buffer();
            width = buffer.width();
            height = buffer.height();
            frames.push(ImageFrame { rgba: buffer.into_raw(), delay: Duration::from_millis(delay_ms as u64) });
        }
        if frames.is_empty() {
            return Err("GIF has no frames".to_string());
        }
        return Ok(DecodedImage { width, height, frames });
    }

    let mut reader = image::ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_SIDE);
    limits.max_image_height = Some(MAX_IMAGE_SIDE);
    limits.max_alloc = Some(MAX_DECODED_BYTES);
    reader.limits(limits);
    let decoded = reader.decode().map_err(|e| e.to_string())?.to_rgba8();
    Ok(DecodedImage {
        width: decoded.width(),
        height: decoded.height(),
        frames: vec![ImageFrame { rgba: decoded.into_raw(), delay: Duration::ZERO }],
    })
}

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

/// What the audio analysis found: format details and a waveform overview.
#[derive(Clone, Debug, Default)]
pub struct AudioInfo {
    pub codec: String,
    pub sample_rate: u32,
    pub channels: usize,
    pub duration: Duration,
    /// Peak amplitude (0 to 1) per bucket across the whole track.
    pub peaks: Vec<f32>,
}

/// Decode the whole track once to measure it and build `buckets` peaks.
pub fn analyse_audio(bytes: Vec<u8>, buckets: usize) -> Result<AudioInfo, String> {
    let source = MediaSourceStream::new(Box::new(Cursor::new(bytes)), Default::default());
    let probed = symphonia::default::get_probe()
        .format(&Hint::new(), source, &FormatOptions::default(), &MetadataOptions::default())
        .map_err(|e| format!("not a recognised audio stream: {e}"))?;
    let mut format = probed.format;
    let track = format
        .tracks()
        .iter()
        .find(|track| track.codec_params.codec != CODEC_TYPE_NULL)
        .ok_or("no audio track")?
        .clone();
    let codec_name = symphonia::default::get_codecs()
        .get_codec(track.codec_params.codec)
        .map(|descriptor| descriptor.short_name.to_string())
        .unwrap_or_else(|| "audio".to_string());
    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|e| e.to_string())?;

    let mut sample_rate = track.codec_params.sample_rate.unwrap_or(0);
    let mut channels = track.codec_params.channels.map(|c| c.count()).unwrap_or(0);
    // Mono mix of absolute amplitudes, reduced on the fly to keep memory small.
    let mut amplitudes: Vec<f32> = Vec::new();
    let mut frames_seen: u64 = 0;
    while let Ok(packet) = format.next_packet() {
        if packet.track_id() != track.id {
            continue;
        }
        let Ok(decoded) = decoder.decode(&packet) else { continue };
        let spec = *decoded.spec();
        sample_rate = spec.rate;
        channels = spec.channels.count().max(1);
        let mut buffer = SampleBuffer::<f32>::new(decoded.capacity() as u64, spec);
        buffer.copy_interleaved_ref(decoded);
        for frame in buffer.samples().chunks(channels) {
            let level = frame.iter().fold(0.0f32, |peak, s| peak.max(s.abs()));
            amplitudes.push(level);
        }
        frames_seen += (buffer.samples().len() / channels) as u64;
        // Halve the resolution whenever the buffer grows large.
        if amplitudes.len() > buckets * 64 {
            amplitudes = amplitudes.chunks(2).map(|pair| pair.iter().copied().fold(0.0, f32::max)).collect();
        }
    }
    if frames_seen == 0 {
        return Err("audio stream decoded to nothing".to_string());
    }
    let duration = if sample_rate > 0 {
        Duration::from_secs_f64(frames_seen as f64 / sample_rate as f64)
    } else {
        Duration::ZERO
    };
    Ok(AudioInfo { codec: codec_name, sample_rate, channels, duration, peaks: reduce_peaks(&amplitudes, buckets) })
}

fn reduce_peaks(levels: &[f32], buckets: usize) -> Vec<f32> {
    if levels.is_empty() || buckets == 0 {
        return Vec::new();
    }
    // Spread the levels evenly so there are exactly `buckets` values.
    let buckets = buckets.min(levels.len());
    (0..buckets)
        .map(|bucket| {
            let start = bucket * levels.len() / buckets;
            let end = ((bucket + 1) * levels.len() / buckets).max(start + 1);
            levels[start..end].iter().copied().fold(0.0, f32::max).min(1.0)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Video via ffmpeg
// ---------------------------------------------------------------------------

/// Whether `ffmpeg` and `ffprobe` can be run.
pub fn ffmpeg_available() -> bool {
    let works = |tool: &str| Command::new(tool).arg("-version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    works("ffmpeg") && works("ffprobe")
}

/// Write `bytes` to a temporary file the external tools can read.
pub fn write_temp(bytes: &[u8], extension: &str) -> Result<PathBuf, String> {
    let name = format!("theviewer-media-{}-{}.{extension}", std::process::id(), unique_suffix());
    let path = std::env::temp_dir().join(name);
    let mut file = std::fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    Ok(path)
}

fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Stream details from `ffprobe`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VideoInfo {
    pub width: u32,
    pub height: u32,
    pub fps: f64,
    pub duration: Duration,
    pub video_codec: String,
    pub audio_codec: Option<String>,
}

/// Ask `ffprobe` about the file's first video stream and any audio.
pub fn probe_video(path: &Path) -> Result<VideoInfo, String> {
    let output = Command::new("ffprobe")
        .args(["-v", "error", "-show_entries", "stream=codec_type,codec_name,width,height,avg_frame_rate,r_frame_rate:format=duration", "-of", "default=noprint_wrappers=0"])
        .arg(path)
        .output()
        .map_err(|e| format!("ffprobe: {e}"))?;
    if !output.status.success() {
        return Err(format!("ffprobe could not read the stream: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    parse_probe(&String::from_utf8_lossy(&output.stdout))
}

/// Parse `ffprobe`'s default output: `[STREAM]`/`[FORMAT]` sections of
/// `key=value` lines.
fn parse_probe(text: &str) -> Result<VideoInfo, String> {
    let mut info = VideoInfo::default();
    let mut section: Vec<(String, String)> = Vec::new();
    let mut saw_video = false;
    let mut flush = |section: &mut Vec<(String, String)>, info: &mut VideoInfo| {
        let get = |key: &str| section.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        match get("codec_type") {
            Some("video") if !saw_video => {
                saw_video = true;
                info.video_codec = get("codec_name").unwrap_or("video").to_string();
                info.width = get("width").and_then(|v| v.parse().ok()).unwrap_or(0);
                info.height = get("height").and_then(|v| v.parse().ok()).unwrap_or(0);
                let rate = get("avg_frame_rate").and_then(parse_rate).or_else(|| get("r_frame_rate").and_then(parse_rate));
                info.fps = rate.unwrap_or(25.0);
            }
            Some("audio") if info.audio_codec.is_none() => {
                info.audio_codec = get("codec_name").map(str::to_string);
            }
            _ => {}
        }
        if let Some(duration) = get("duration").and_then(|v| v.parse::<f64>().ok()) {
            info.duration = Duration::from_secs_f64(duration.max(0.0));
        }
        section.clear();
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("[/") {
            flush(&mut section, &mut info);
        } else if let Some((key, value)) = line.split_once('=') {
            section.push((key.to_string(), value.to_string()));
        }
    }
    flush(&mut section, &mut info);
    if info.width == 0 || info.height == 0 {
        return Err("no video stream".to_string());
    }
    Ok(info)
}

fn parse_rate(text: &str) -> Option<f64> {
    let (numerator, denominator) = text.split_once('/')?;
    let (numerator, denominator): (f64, f64) = (numerator.parse().ok()?, denominator.parse().ok()?);
    (denominator > 0.0 && numerator > 0.0).then_some(numerator / denominator)
}

/// Pick output dimensions that fit `max_side`, keeping the aspect ratio and
/// even sizes (some pixel formats need them).
pub fn fit_dimensions(width: u32, height: u32, max_side: u32) -> (u32, u32) {
    let scale = (max_side as f64 / width.max(height).max(1) as f64).min(1.0);
    let even = |value: f64| ((value.round() as u32).max(2) / 2) * 2;
    (even(width as f64 * scale), even(height as f64 * scale))
}

/// One decoded video frame.
pub struct VideoFrame {
    pub rgba: Vec<u8>,
    /// Presentation time from the start of the file.
    pub time: Duration,
}

/// A running `ffmpeg` that decodes frames from `start` onwards on a
/// background thread. Dropping it stops the decoder.
pub struct FrameStream {
    child: Child,
    pub frames: Receiver<VideoFrame>,
}

impl FrameStream {
    /// Decode frames of `width`×`height` RGBA, `fps` per second, from `start`.
    /// At most `buffer` frames are decoded ahead; the decoder blocks beyond that.
    pub fn start(path: &Path, start: Duration, width: u32, height: u32, fps: f64, buffer: usize) -> Result<FrameStream, String> {
        let mut child = Command::new("ffmpeg")
            .args(["-v", "error", "-nostdin", "-ss"])
            .arg(format!("{:.3}", start.as_secs_f64()))
            .arg("-i")
            .arg(path)
            .args(["-an", "-sn", "-f", "rawvideo", "-pix_fmt", "rgba", "-vf"])
            .arg(format!("scale={width}:{height}:flags=bilinear"))
            .arg("-")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("ffmpeg: {e}"))?;
        let mut stdout = child.stdout.take().ok_or("ffmpeg gave no output")?;
        let (sender, receiver): (SyncSender<VideoFrame>, Receiver<VideoFrame>) = mpsc::sync_channel(buffer.max(1));
        let frame_len = width as usize * height as usize * 4;
        let frame_time = Duration::from_secs_f64(1.0 / fps.max(1.0));
        thread::spawn(move || {
            let mut index: u32 = 0;
            loop {
                let mut rgba = vec![0u8; frame_len];
                if stdout.read_exact(&mut rgba).is_err() {
                    break;
                }
                let time = start + frame_time * index;
                if sender.send(VideoFrame { rgba, time }).is_err() {
                    break;
                }
                index += 1;
            }
        });
        Ok(FrameStream { child, frames: receiver })
    }
}

impl Drop for FrameStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Decode the audio track from `start` to a WAV in memory, for playback in
/// step with the frames.
pub fn extract_audio_wav(path: &Path, start: Duration) -> Result<Vec<u8>, String> {
    let output = Command::new("ffmpeg")
        .args(["-v", "error", "-nostdin", "-ss"])
        .arg(format!("{:.3}", start.as_secs_f64()))
        .arg("-i")
        .arg(path)
        .args(["-vn", "-ac", "2", "-ar", "44100", "-f", "wav", "-"])
        .output()
        .map_err(|e| format!("ffmpeg: {e}"))?;
    if !output.status.success() || output.stdout.len() <= 44 {
        return Err("no audio track".to_string());
    }
    Ok(output.stdout)
}

/// Hand the file to the operating system's default player.
pub fn open_externally(path: &Path) -> Result<(), String> {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    Command::new(program).arg(path).spawn().map(|_| ()).map_err(|e| format!("{program}: {e}"))
}

/// File extension to use for a temporary copy of a format.
pub fn extension_for(format: &MediaFormat) -> &'static str {
    match format.name {
        "WAV" => "wav",
        "AVI" => "avi",
        "WebP" => "webp",
        "M4A" => "m4a",
        "QuickTime" => "mov",
        "MP4" | "HEIF/AVIF" => "mp4",
        "WebM" => "webm",
        "Matroska" => "mkv",
        "Ogg Theora" => "ogv",
        "Ogg Opus" => "opus",
        "Ogg Vorbis" => "ogg",
        "FLV" => "flv",
        "MPEG-TS" => "ts",
        "FLAC" => "flac",
        "MP3" => "mp3",
        "AIFF" => "aiff",
        "CAF" => "caf",
        "AAC (ADTS)" => "aac",
        "PNG" => "png",
        "JPEG" => "jpg",
        "GIF" => "gif",
        "BMP" => "bmp",
        "TIFF" => "tiff",
        "ICO" => "ico",
        _ => "bin",
    }
}

/// `m:ss` or `h:mm:ss`.
pub fn format_time(duration: Duration) -> String {
    let total = duration.as_secs();
    let (hours, minutes, seconds) = (total / 3600, (total / 60) % 60, total % 60);
    if hours > 0 { format!("{hours}:{minutes:02}:{seconds:02}") } else { format!("{minutes}:{seconds:02}") }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn a_gif_declaring_a_huge_screen_is_refused_before_decoding() {
        // A 20000 × 20000 logical screen holding one 1 × 1 frame: a few bytes
        // that would need 1.6 GB per composited frame.
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&20_000u16.to_le_bytes());
        gif.extend_from_slice(&20_000u16.to_le_bytes());
        gif.extend_from_slice(&[0x80, 0, 0]); // two-colour global palette follows
        gif.extend_from_slice(&[0, 0, 0, 255, 255, 255]);
        gif.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0]); // 1 × 1 image
        gif.extend_from_slice(&[0x02, 0x02, 0x44, 0x01, 0x00, 0x3B]); // pixel data, trailer
        let error = decode_image(&gif).err().expect("refused");
        assert!(error.contains("20000"), "{error}");
    }

    /// A mono 16-bit WAV: one second of a 440 Hz tone that fades out.
    pub fn sine_wav(seconds: f32) -> Vec<u8> {
        let rate = 8000u32;
        let samples = (rate as f32 * seconds) as usize;
        let mut data = Vec::with_capacity(samples * 2);
        for n in 0..samples {
            let fade = 1.0 - n as f32 / samples as f32;
            let value = (n as f32 * 440.0 * std::f32::consts::TAU / rate as f32).sin() * fade * 0.8;
            data.extend_from_slice(&((value * i16::MAX as f32) as i16).to_le_bytes());
        }
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&rate.to_le_bytes());
        wav.extend_from_slice(&(rate * 2).to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&(data.len() as u32).to_le_bytes());
        wav.extend_from_slice(&data);
        wav
    }

    fn png_bytes(width: u32, height: u32) -> Vec<u8> {
        let image = image::RgbaImage::from_fn(width, height, |x, y| image::Rgba([x as u8 * 10, y as u8 * 20, 128, 255]));
        let mut out = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image).write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    #[test]
    fn detects_common_media_by_their_headers() {
        let kind = |bytes: &[u8]| detect(bytes).map(|f| (f.kind, f.name));
        assert_eq!(kind(&sine_wav(0.1)), Some((MediaKind::Audio, "WAV")));
        assert_eq!(kind(&png_bytes(2, 2)), Some((MediaKind::Image, "PNG")));
        assert_eq!(kind(b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00"), Some((MediaKind::Video, "MP4")));
        assert_eq!(kind(b"\x00\x00\x00\x20ftypM4A \x00\x00\x02\x00"), Some((MediaKind::Audio, "M4A")));
        assert_eq!(kind(b"\x1A\x45\xDF\xA3\x9F\x42\x86\x81\x01\x42\x82\x84webm"), Some((MediaKind::Video, "WebM")));
        assert_eq!(kind(b"fLaC\x00\x00\x00\x22"), Some((MediaKind::Audio, "FLAC")));
        assert_eq!(kind(b"ID3\x04\x00\x00\x00\x00\x00\x00"), Some((MediaKind::Audio, "MP3")));
        assert_eq!(kind(b"just some text, not media"), None);
        assert_eq!(kind(b"RIFF\x00\x00\x00\x00XXXX"), None);
    }

    #[test]
    fn mp3_frames_need_a_second_frame_to_count() {
        // 128 kbit/s, 44.1 kHz frame: 417 bytes.
        let mut stream = vec![0u8; 417 * 2];
        stream[0..4].copy_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        assert!(!is_mpeg_audio_frame(&stream));
        stream[417..421].copy_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        assert!(is_mpeg_audio_frame(&stream));
    }

    #[test]
    fn decodes_stills_and_animation_frames() {
        let still = decode_image(&png_bytes(5, 3)).unwrap();
        assert_eq!((still.width, still.height, still.frames.len()), (5, 3, 1));
        assert_eq!(still.frames[0].rgba.len(), 5 * 3 * 4);

        let mut gif = Vec::new();
        {
            let mut encoder = image::codecs::gif::GifEncoder::new(&mut gif);
            for shade in [0u8, 128, 255] {
                let frame = image::Frame::from_parts(
                    image::RgbaImage::from_pixel(4, 4, image::Rgba([shade, 0, 0, 255])),
                    0,
                    0,
                    image::Delay::from_numer_denom_ms(100, 1),
                );
                encoder.encode_frame(frame).unwrap();
            }
        }
        let animation = decode_image(&gif).unwrap();
        assert_eq!(animation.frames.len(), 3);
        assert_eq!(animation.frames[1].delay, Duration::from_millis(100));
    }

    #[test]
    fn audio_analysis_measures_duration_and_builds_a_fading_waveform() {
        let info = analyse_audio(sine_wav(1.0), 100).unwrap();
        assert_eq!((info.sample_rate, info.channels), (8000, 1));
        assert!((info.duration.as_secs_f64() - 1.0).abs() < 0.01, "{:?}", info.duration);
        assert_eq!(info.peaks.len(), 100);
        assert!(info.peaks[0] > 0.7 && info.peaks[99] < 0.1, "{:?}", (info.peaks[0], info.peaks[99]));
        assert!(analyse_audio(b"not audio at all".to_vec(), 10).is_err());
    }

    #[test]
    fn probe_output_and_dimensions_are_parsed() {
        let text = "[STREAM]\ncodec_name=h264\ncodec_type=video\nwidth=1920\nheight=1080\nr_frame_rate=30/1\navg_frame_rate=30000/1001\n[/STREAM]\n[STREAM]\ncodec_name=aac\ncodec_type=audio\n[/STREAM]\n[FORMAT]\nduration=12.5\n[/FORMAT]\n";
        let info = parse_probe(text).unwrap();
        assert_eq!((info.width, info.height, info.video_codec.as_str()), (1920, 1080, "h264"));
        assert!((info.fps - 29.97).abs() < 0.01);
        assert_eq!(info.audio_codec.as_deref(), Some("aac"));
        assert_eq!(info.duration, Duration::from_secs_f64(12.5));
        assert!(parse_probe("[FORMAT]\nduration=1\n[/FORMAT]\n").is_err());
        assert_eq!(fit_dimensions(1920, 1080, 960), (960, 540));
        assert_eq!(fit_dimensions(101, 51, 2000), (100, 50));
        assert_eq!(format_time(Duration::from_secs(3725)), "1:02:05");
        assert_eq!(format_time(Duration::from_secs(65)), "1:05");
    }

    /// Exercises the real ffmpeg pipeline when the tools are installed.
    #[test]
    fn ffmpeg_decodes_frames_and_audio_from_a_generated_clip() {
        if !ffmpeg_available() {
            eprintln!("ffmpeg not installed; skipping");
            return;
        }
        let path = std::env::temp_dir().join(format!("theviewer-clip-{}.mp4", std::process::id()));
        let status = Command::new("ffmpeg")
            .args(["-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=64x48:rate=10", "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=8000", "-t", "1", "-pix_fmt", "yuv420p", "-shortest"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(detect(&bytes).map(|f| f.kind), Some(MediaKind::Video));

        let info = probe_video(&path).unwrap();
        assert_eq!((info.width, info.height), (64, 48));
        assert!((info.fps - 10.0).abs() < 0.01);
        assert!(info.audio_codec.is_some());

        let stream = FrameStream::start(&path, Duration::ZERO, 32, 24, info.fps, 4).unwrap();
        let frames: Vec<VideoFrame> = stream.frames.iter().take(5).collect();
        assert_eq!(frames.len(), 5);
        assert_eq!(frames[0].rgba.len(), 32 * 24 * 4);
        assert_eq!(frames[4].time, Duration::from_millis(400));

        let wav = extract_audio_wav(&path, Duration::from_millis(500)).unwrap();
        assert_eq!(detect(&wav).map(|f| f.name), Some("WAV"));
        std::fs::remove_file(&path).ok();
    }
}
