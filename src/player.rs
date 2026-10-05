//! The media window: an image viewer, an audio player and a video player for
//! media found inside the document.
//!
//! Decoding happens on background threads; this module owns the textures,
//! the audio output and the playback clocks.

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, ColorImage, Context, Pos2, Rect, RichText, Sense, Stroke, TextureHandle, TextureOptions, Ui, Vec2, pos2, vec2};

use crate::media::{self, AudioInfo, DecodedImage, FrameStream, MediaFormat, MediaKind, VideoInfo};
use crate::theme;

/// Waveform resolution.
const WAVEFORM_BUCKETS: usize = 1200;
/// Largest side of decoded video frames.
const VIDEO_MAX_SIDE: u32 = 960;
/// Frames decoded ahead of the clock.
const VIDEO_BUFFER_FRAMES: usize = 8;

/// The bytes to open, with where they came from.
pub struct MediaRequest {
    pub format: MediaFormat,
    pub start: usize,
    pub bytes: Vec<u8>,
    pub source_name: String,
}

/// The media window's state; `None` content means the window is closed.
#[derive(Default)]
pub struct MediaPlayer {
    window: Option<MediaWindow>,
    /// Opened lazily the first time something plays, and kept for reuse.
    audio_device: Option<rodio::MixerDeviceSink>,
    audio_device_error: Option<String>,
}

struct MediaWindow {
    title: String,
    format: MediaFormat,
    start: usize,
    bytes: Arc<Vec<u8>>,
    content: Content,
    status: String,
}

enum Content {
    Image(ImageView),
    Audio(AudioView),
    Video(Box<VideoView>),
    Failed(String),
}

impl MediaPlayer {
    pub fn is_open(&self) -> bool {
        self.window.is_some()
    }

    /// Title of what is open, for tests and the status bar.
    pub fn title(&self) -> Option<&str> {
        self.window.as_ref().map(|window| window.title.as_str())
    }

    /// Kind of what is open.
    pub fn kind(&self) -> Option<MediaKind> {
        self.window.as_ref().map(|window| window.format.kind)
    }

    /// Whether audio or video is currently playing.
    pub fn is_playing(&self) -> bool {
        match self.window.as_ref().map(|w| &w.content) {
            Some(Content::Audio(audio)) => audio.playing,
            Some(Content::Video(video)) => video.playing,
            Some(Content::Image(image)) => image.animating,
            _ => false,
        }
    }

    /// Any decode error the open media reported, for tests and diagnostics.
    pub fn error_text(&self) -> Option<String> {
        match self.window.as_ref().map(|w| &w.content) {
            Some(Content::Failed(message)) => Some(message.clone()),
            Some(Content::Image(image)) => image.error.clone(),
            Some(Content::Audio(audio)) => audio.error.clone(),
            _ => None,
        }
    }

    /// Error shown in the window, if opening failed.
    pub fn error(&self) -> Option<&str> {
        match self.window.as_ref().map(|w| &w.content) {
            Some(Content::Failed(message)) => Some(message),
            _ => None,
        }
    }

    pub fn close(&mut self) {
        self.window = None;
    }

    /// Whether the open media has finished its first decode: the image or
    /// first video frame is ready, or the audio has been analysed.
    pub fn is_ready(&self) -> bool {
        match self.window.as_ref().map(|w| &w.content) {
            Some(Content::Image(image)) => image.image.is_some(),
            Some(Content::Audio(audio)) => audio.info.is_some(),
            Some(Content::Video(video)) => video.texture.is_some(),
            _ => false,
        }
    }

    /// Duration of the open audio or video, once known.
    pub fn duration(&self) -> Option<Duration> {
        match self.window.as_ref().map(|w| &w.content) {
            Some(Content::Audio(audio)) => audio.info.as_ref().map(|info| info.duration),
            Some(Content::Video(video)) => Some(video.info.duration),
            _ => None,
        }
    }

    /// Open `request` in the window, replacing whatever was there.
    pub fn open(&mut self, request: MediaRequest) {
        let title = format!("{} at {:#x} in {}", request.format.name, request.start, request.source_name);
        let bytes = Arc::new(request.bytes);
        let content = match request.format.kind {
            MediaKind::Image => Content::Image(ImageView::start(Arc::clone(&bytes))),
            MediaKind::Audio => Content::Audio(AudioView::start(Arc::clone(&bytes))),
            MediaKind::Video => match VideoView::start(&bytes, &request.format) {
                Ok(video) => Content::Video(Box::new(video)),
                Err(message) => Content::Failed(message),
            },
        };
        self.window = Some(MediaWindow { title, format: request.format, start: request.start, bytes, content, status: String::new() });
    }

    fn audio_output(&mut self) -> Option<&rodio::MixerDeviceSink> {
        if self.audio_device.is_none() && self.audio_device_error.is_none() {
            match rodio::DeviceSinkBuilder::open_default_sink() {
                Ok(mut device) => {
                    device.log_on_drop(false);
                    self.audio_device = Some(device);
                }
                Err(error) => self.audio_device_error = Some(format!("No audio output: {error}")),
            }
        }
        self.audio_device.as_ref()
    }

    /// Draw the window, if anything is open.
    pub fn show(&mut self, ctx: &Context) {
        // Take the window out so the audio device beside it can be borrowed too.
        let Some(mut window) = self.window.take() else { return };
        let mut open = true;
        let title = window.title.clone();
        egui::Window::new(RichText::new(&title).strong())
            .id(egui::Id::new("media-window"))
            .open(&mut open)
            .default_size([680.0, 520.0])
            .resizable(true)
            .collapsible(false)
            .show(ctx, |ui| self.show_contents(ui, &mut window));
        if open {
            self.window = Some(window);
        }
    }

    fn show_contents(&mut self, ui: &mut Ui, window: &mut MediaWindow) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} · {} bytes from {:#x}", window.format.name, window.bytes.len(), window.start)).color(theme::TEXT_DIM));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Open externally").on_hover_text("Hand a copy to the system's default app").clicked() {
                    window.status = match media::write_temp(&window.bytes, media::extension_for(&window.format)).and_then(|path| media::open_externally(&path)) {
                        Ok(()) => "Opened in the system player".to_string(),
                        Err(message) => message,
                    };
                }
                if ui.button("Save…").on_hover_text("Save these bytes to a file").clicked() {
                    let name = format!("media-{:#x}.{}", window.start, media::extension_for(&window.format));
                    if let Some(path) = rfd::FileDialog::new().set_file_name(name).save_file() {
                        window.status = match std::fs::write(&path, window.bytes.as_slice()) {
                            Ok(()) => format!("Saved to {}", path.display()),
                            Err(error) => error.to_string(),
                        };
                    }
                }
            });
        });
        if !window.status.is_empty() {
            ui.label(RichText::new(&window.status).small().color(theme::TEXT_DIM));
        }
        ui.separator();
        match &mut window.content {
            Content::Image(image) => image.show(ui),
            Content::Audio(audio) => {
                let output = self.audio_output().map(|device| device.mixer().clone());
                audio.show(ui, output.as_ref(), self.audio_device_error.as_deref());
            }
            Content::Video(video) => {
                let output = self.audio_output().map(|device| device.mixer().clone());
                video.show(ui, output.as_ref());
            }
            Content::Failed(message) => {
                ui.label(RichText::new(message.as_str()).color(theme::DANGER));
                ui.label(RichText::new("Try “Open externally” to use the system player.").color(theme::TEXT_DIM));
            }
        }
    }

    /// Space toggles play and pause while the window is open.
    pub fn toggle_play(&mut self) {
        let Some(window) = self.window.as_mut() else { return };
        match &mut window.content {
            Content::Audio(audio) => audio.toggle(),
            Content::Video(video) => video.toggle(),
            Content::Image(image) => image.animating = !image.animating,
            Content::Failed(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Image viewer
// ---------------------------------------------------------------------------

struct ImageView {
    pending: Option<Receiver<Result<DecodedImage, String>>>,
    image: Option<DecodedImage>,
    error: Option<String>,
    textures: Vec<TextureHandle>,
    frame: usize,
    frame_shown_at: Instant,
    animating: bool,
    /// `None` fits the window; otherwise pixels per image pixel.
    zoom: Option<f32>,
    pan: Vec2,
}

impl ImageView {
    fn start(bytes: Arc<Vec<u8>>) -> Self {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(media::decode_image(&bytes));
        });
        ImageView {
            pending: Some(receiver),
            image: None,
            error: None,
            textures: Vec::new(),
            frame: 0,
            frame_shown_at: Instant::now(),
            animating: true,
            zoom: None,
            pan: Vec2::ZERO,
        }
    }

    fn poll(&mut self, ctx: &Context) {
        let Some(receiver) = &self.pending else { return };
        match receiver.try_recv() {
            Ok(Ok(image)) => {
                let size = [image.width as usize, image.height as usize];
                self.textures = image
                    .frames
                    .iter()
                    .enumerate()
                    .map(|(index, frame)| ctx.load_texture(format!("media-image-{index}"), ColorImage::from_rgba_unmultiplied(size, &frame.rgba), TextureOptions::NEAREST))
                    .collect();
                self.image = Some(image);
                self.pending = None;
            }
            Ok(Err(message)) => {
                self.error = Some(message);
                self.pending = None;
            }
            Err(mpsc::TryRecvError::Empty) => ctx.request_repaint_after(Duration::from_millis(30)),
            Err(mpsc::TryRecvError::Disconnected) => self.pending = None,
        }
    }

    fn show(&mut self, ui: &mut Ui) {
        self.poll(ui.ctx());
        if let Some(message) = &self.error {
            ui.label(RichText::new(format!("Could not decode the image: {message}")).color(theme::DANGER));
            return;
        }
        let Some(image) = &self.image else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Decoding…");
            });
            return;
        };
        let (width, height) = (image.width, image.height);
        let animated = image.frames.len() > 1;
        if animated && self.animating {
            let delay = image.frames[self.frame].delay;
            if self.frame_shown_at.elapsed() >= delay {
                self.frame = (self.frame + 1) % image.frames.len();
                self.frame_shown_at = Instant::now();
            }
            ui.ctx().request_repaint_after(delay.saturating_sub(self.frame_shown_at.elapsed()));
        }

        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{width}×{height}")).monospace());
            if animated {
                ui.label(RichText::new(format!("frame {}/{}", self.frame + 1, image.frames.len())).color(theme::TEXT_DIM));
                if ui.button(if self.animating { "Pause" } else { "Play" }).clicked() {
                    self.animating = !self.animating;
                }
                if ui.button("Next frame").clicked() {
                    self.animating = false;
                    self.frame = (self.frame + 1) % image.frames.len();
                }
            }
            ui.separator();
            if ui.selectable_label(self.zoom.is_none(), "Fit").clicked() {
                self.zoom = None;
                self.pan = Vec2::ZERO;
            }
            for factor in [1.0f32, 2.0, 4.0, 8.0] {
                if ui.selectable_label(self.zoom == Some(factor), format!("{factor}×")).clicked() {
                    self.zoom = Some(factor);
                    self.pan = Vec2::ZERO;
                }
            }
        });

        let (rect, response) = ui.allocate_exact_size(ui.available_size().max(vec2(64.0, 64.0)), Sense::click_and_drag());
        let painter = ui.painter_at(rect);
        draw_checkerboard(&painter, rect);
        let image_size = vec2(width as f32, height as f32);
        let scale = self.zoom.unwrap_or_else(|| (rect.width() / image_size.x).min(rect.height() / image_size.y).min(8.0));
        if response.dragged() && self.zoom.is_some() {
            self.pan += response.drag_delta();
        }
        if response.hovered() {
            let zoom_delta = ui.input(|i| i.zoom_delta());
            if (zoom_delta - 1.0).abs() > 1e-3 {
                self.zoom = Some((scale * zoom_delta).clamp(0.05, 64.0));
            }
        }
        let drawn = Rect::from_center_size(rect.center() + self.pan, image_size * scale);
        let texture = &self.textures[self.frame.min(self.textures.len() - 1)];
        painter.image(texture.id(), drawn, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);

        // Pixel readout under the pointer.
        if let Some(pointer) = response.hover_pos()
            && drawn.contains(pointer)
        {
            let x = ((pointer.x - drawn.min.x) / scale) as u32;
            let y = ((pointer.y - drawn.min.y) / scale) as u32;
            let at = ((y.min(height - 1) * width + x.min(width - 1)) * 4) as usize;
            let rgba = &image.frames[self.frame].rgba[at..at + 4];
            let text = format!("({x}, {y})  #{:02X}{:02X}{:02X}  alpha {}", rgba[0], rgba[1], rgba[2], rgba[3]);
            painter.text(rect.left_bottom() + vec2(6.0, -6.0), egui::Align2::LEFT_BOTTOM, text, egui::FontId::monospace(12.0), theme::TEXT);
        }
    }
}

fn draw_checkerboard(painter: &egui::Painter, rect: Rect) {
    const CELL: f32 = 12.0;
    painter.rect_filled(rect, 0.0, Color32::from_gray(44));
    let columns = (rect.width() / CELL).ceil() as i32;
    let rows = (rect.height() / CELL).ceil() as i32;
    for row in 0..rows {
        for column in 0..columns {
            if (row + column) % 2 == 0 {
                let min = rect.min + vec2(column as f32 * CELL, row as f32 * CELL);
                painter.rect_filled(Rect::from_min_size(min, Vec2::splat(CELL)).intersect(rect), 0.0, Color32::from_gray(56));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Audio player
// ---------------------------------------------------------------------------

struct AudioView {
    bytes: Arc<Vec<u8>>,
    pending: Option<Receiver<Result<AudioInfo, String>>>,
    info: Option<AudioInfo>,
    error: Option<String>,
    player: Option<rodio::Player>,
    playing: bool,
    /// Set by the play/pause toggle when no output was available yet.
    want_play: bool,
}

impl AudioView {
    fn start(bytes: Arc<Vec<u8>>) -> Self {
        let (sender, receiver) = mpsc::channel();
        let for_analysis = Arc::clone(&bytes);
        thread::spawn(move || {
            let _ = sender.send(media::analyse_audio(for_analysis.to_vec(), WAVEFORM_BUCKETS));
        });
        AudioView { bytes, pending: Some(receiver), info: None, error: None, player: None, playing: false, want_play: false }
    }

    fn toggle(&mut self) {
        self.want_play = !self.playing;
        if let Some(player) = &self.player {
            if self.playing {
                player.pause();
                self.playing = false;
            } else {
                player.play();
                self.playing = true;
            }
        }
    }

    /// Build a player for the bytes, positioned at `at`.
    fn connect(&mut self, mixer: &rodio::mixer::Mixer, at: Duration) -> Result<(), String> {
        let decoder = rodio::Decoder::builder()
            .with_data(Cursor::new(self.bytes.to_vec()))
            .with_byte_len(self.bytes.len() as u64)
            .with_seekable(true)
            .build()
            .map_err(|e| format!("cannot play this audio: {e}"))?;
        let player = rodio::Player::connect_new(mixer);
        player.append(decoder);
        if !at.is_zero() {
            let _ = player.try_seek(at);
        }
        self.player = Some(player);
        Ok(())
    }

    fn show(&mut self, ui: &mut Ui, mixer: Option<&rodio::mixer::Mixer>, device_error: Option<&str>) {
        if let Some(receiver) = &self.pending {
            match receiver.try_recv() {
                Ok(Ok(info)) => {
                    self.info = Some(info);
                    self.pending = None;
                }
                Ok(Err(message)) => {
                    self.error = Some(message);
                    self.pending = None;
                }
                Err(_) => ui.ctx().request_repaint_after(Duration::from_millis(50)),
            }
        }
        if let Some(message) = &self.error {
            ui.label(RichText::new(format!("Could not decode the audio: {message}")).color(theme::DANGER));
            return;
        }
        if let Some(message) = device_error {
            ui.label(RichText::new(message).color(theme::TEXT_DIM));
        }
        if self.want_play && self.player.is_none()
            && let Some(mixer) = mixer
        {
            match self.connect(mixer, Duration::ZERO) {
                Ok(()) => self.playing = true,
                Err(message) => self.error = Some(message),
            }
        }

        let position = self.player.as_ref().map(|p| p.get_pos()).unwrap_or_default();
        let duration = self.info.as_ref().map(|i| i.duration).unwrap_or_default();
        if self.playing && self.player.as_ref().is_some_and(|p| p.empty()) {
            // Reached the end.
            self.playing = false;
            self.want_play = false;
            self.player = None;
        }

        ui.horizontal(|ui| {
            let label = if self.playing { "Pause" } else { "Play" };
            if ui.add(egui::Button::new(RichText::new(label).strong()).min_size(vec2(64.0, 0.0))).on_hover_text("Space").clicked() {
                if self.player.is_none() && !self.playing {
                    if let Some(mixer) = mixer {
                        match self.connect(mixer, Duration::ZERO) {
                            Ok(()) => self.playing = true,
                            Err(message) => self.error = Some(message),
                        }
                    }
                } else {
                    self.toggle();
                }
            }
            if ui.button("Stop").clicked() {
                self.player = None;
                self.playing = false;
                self.want_play = false;
            }
            ui.label(RichText::new(format!("{} / {}", media::format_time(position), media::format_time(duration))).monospace());
            if let Some(info) = &self.info {
                ui.label(RichText::new(format!("{} · {} Hz · {} ch", info.codec, info.sample_rate, info.channels)).color(theme::TEXT_DIM));
            } else {
                ui.spinner();
            }
        });

        // Waveform with a playhead; click or drag to seek.
        let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 140.0), Sense::click_and_drag());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, theme::BACKGROUND);
        if let Some(info) = &self.info {
            let middle = rect.center().y;
            let columns = rect.width().max(1.0) as usize;
            for column in 0..columns {
                let bucket = column * info.peaks.len() / columns.max(1);
                let peak = info.peaks.get(bucket).copied().unwrap_or(0.0);
                let x = rect.min.x + column as f32;
                let played = duration > Duration::ZERO && (column as f32 / columns as f32) <= position.as_secs_f32() / duration.as_secs_f32();
                let colour = if played { theme::ACCENT } else { theme::ACCENT_DIM };
                let half = peak * rect.height() * 0.48;
                painter.line_segment([pos2(x, middle - half), pos2(x, middle + half)], Stroke::new(1.0, colour));
            }
            if duration > Duration::ZERO {
                let x = rect.min.x + rect.width() * (position.as_secs_f32() / duration.as_secs_f32()).clamp(0.0, 1.0);
                painter.line_segment([pos2(x, rect.min.y), pos2(x, rect.max.y)], Stroke::new(2.0, theme::CURSOR));
            }
            if let Some(pointer) = response.interact_pointer_pos()
                && (response.clicked() || response.dragged())
                && duration > Duration::ZERO
            {
                let fraction = ((pointer.x - rect.min.x) / rect.width()).clamp(0.0, 1.0);
                let target = duration.mul_f32(fraction);
                self.seek(target, mixer);
            }
        }
        if self.playing {
            ui.ctx().request_repaint_after(Duration::from_millis(33));
        }
    }

    fn seek(&mut self, target: Duration, mixer: Option<&rodio::mixer::Mixer>) {
        if let Some(player) = &self.player
            && player.try_seek(target).is_ok()
        {
            return;
        }
        // Not seekable in place: rebuild the player at the target.
        if let Some(mixer) = mixer {
            let was_playing = self.playing;
            if self.connect(mixer, target).is_ok() && !was_playing
                && let Some(player) = &self.player
            {
                player.pause();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Video player
// ---------------------------------------------------------------------------

struct VideoView {
    path: PathBuf,
    info: VideoInfo,
    size: (u32, u32),
    stream: Option<FrameStream>,
    texture: Option<TextureHandle>,
    /// Time of the frame on screen.
    shown_time: Duration,
    /// Playback clock: position at `clock_base_instant`.
    clock_base: Duration,
    clock_base_instant: Instant,
    playing: bool,
    audio: Option<rodio::Player>,
    audio_pending: Option<Receiver<Result<Vec<u8>, String>>>,
    /// Start position the pending audio was extracted from.
    audio_from: Duration,
    ended: bool,
}

impl VideoView {
    fn start(bytes: &[u8], format: &MediaFormat) -> Result<Self, String> {
        if !media::ffmpeg_available() {
            return Err("Video playback needs ffmpeg (brew install ffmpeg).".to_string());
        }
        let path = media::write_temp(bytes, media::extension_for(format))?;
        let info = media::probe_video(&path)?;
        let size = media::fit_dimensions(info.width, info.height, VIDEO_MAX_SIDE);
        let mut view = VideoView {
            path,
            info,
            size,
            stream: None,
            texture: None,
            shown_time: Duration::ZERO,
            clock_base: Duration::ZERO,
            clock_base_instant: Instant::now(),
            playing: false,
            audio: None,
            audio_pending: None,
            audio_from: Duration::ZERO,
            ended: false,
        };
        // Show the first frame straight away, paused.
        view.restart_stream(Duration::ZERO)?;
        Ok(view)
    }

    fn position(&self) -> Duration {
        if self.playing { self.clock_base + self.clock_base_instant.elapsed() } else { self.clock_base }
    }

    fn restart_stream(&mut self, at: Duration) -> Result<(), String> {
        self.stream = None;
        self.stream = Some(FrameStream::start(&self.path, at, self.size.0, self.size.1, self.info.fps, VIDEO_BUFFER_FRAMES)?);
        self.clock_base = at;
        self.clock_base_instant = Instant::now();
        self.shown_time = at;
        self.ended = false;
        Ok(())
    }

    fn start_audio(&mut self, at: Duration) {
        self.audio = None;
        if self.info.audio_codec.is_none() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let path = self.path.clone();
        thread::spawn(move || {
            let _ = sender.send(media::extract_audio_wav(&path, at));
        });
        self.audio_pending = Some(receiver);
        self.audio_from = at;
    }

    fn toggle(&mut self) {
        if self.playing {
            self.clock_base = self.position();
            self.playing = false;
            if let Some(audio) = &self.audio {
                audio.pause();
            }
        } else {
            if self.ended {
                let _ = self.restart_stream(Duration::ZERO);
            }
            self.clock_base_instant = Instant::now();
            self.playing = true;
            match &self.audio {
                Some(audio) => audio.play(),
                None => self.start_audio(self.clock_base),
            }
        }
    }

    fn seek(&mut self, target: Duration) {
        let target = target.min(self.info.duration);
        if self.restart_stream(target).is_ok() {
            self.texture = None;
            if self.playing {
                self.start_audio(target);
            } else {
                self.audio = None;
            }
        }
    }

    /// Pull frames up to the clock and show the latest.
    fn advance(&mut self, ctx: &Context, step_one: bool) {
        let now = self.position();
        let mut latest = None;
        if let Some(stream) = &self.stream {
            loop {
                match stream.frames.try_recv() {
                    Ok(frame) => {
                        let due = frame.time <= now || self.texture.is_none() || step_one;
                        latest = Some(frame);
                        if !due || step_one {
                            break;
                        }
                        if !self.playing {
                            break;
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        if self.playing && now >= self.shown_time {
                            self.ended = true;
                            self.playing = false;
                            self.clock_base = self.shown_time;
                        }
                        break;
                    }
                }
            }
        }
        if let Some(frame) = latest {
            let image = ColorImage::from_rgba_unmultiplied([self.size.0 as usize, self.size.1 as usize], &frame.rgba);
            match &mut self.texture {
                Some(texture) => texture.set(image, TextureOptions::LINEAR),
                None => self.texture = Some(ctx.load_texture("media-video", image, TextureOptions::LINEAR)),
            }
            self.shown_time = frame.time;
            if step_one {
                self.clock_base = frame.time;
            }
        }
    }

    fn show(&mut self, ui: &mut Ui, mixer: Option<&rodio::mixer::Mixer>) {
        if let Some(receiver) = &self.audio_pending
            && let Ok(result) = receiver.try_recv()
        {
            self.audio_pending = None;
            if let (Ok(wav), Some(mixer)) = (result, mixer)
                && let Ok(decoder) = rodio::Decoder::new(Cursor::new(wav))
            {
                let player = rodio::Player::connect_new(mixer);
                player.append(decoder);
                // Catch up with the clock, which kept running while extracting.
                let behind = self.position().saturating_sub(self.audio_from);
                let _ = player.try_seek(behind);
                if !self.playing {
                    player.pause();
                }
                self.audio = Some(player);
            }
        }

        let mut step_one = false;
        ui.horizontal(|ui| {
            let label = if self.playing { "Pause" } else { "Play" };
            if ui.add(egui::Button::new(RichText::new(label).strong()).min_size(vec2(64.0, 0.0))).on_hover_text("Space").clicked() {
                self.toggle();
            }
            if ui.add_enabled(!self.playing, egui::Button::new("Next frame")).clicked() {
                step_one = true;
            }
            ui.label(RichText::new(format!("{} / {}", media::format_time(self.position()), media::format_time(self.info.duration))).monospace());
            let audio = self.info.audio_codec.as_deref().map(|codec| format!(" · audio {codec}")).unwrap_or_default();
            ui.label(RichText::new(format!("{} {}×{} @ {:.2} fps{audio}", self.info.video_codec, self.info.width, self.info.height, self.info.fps)).color(theme::TEXT_DIM));
        });
        self.advance(ui.ctx(), step_one);

        // Seek bar.
        let (bar, bar_response) = ui.allocate_exact_size(vec2(ui.available_width(), 14.0), Sense::click_and_drag());
        let painter = ui.painter_at(bar);
        painter.rect_filled(bar.shrink2(vec2(0.0, 4.0)), 3.0, theme::SURFACE_RAISED);
        let duration = self.info.duration.as_secs_f32().max(0.001);
        let fraction = (self.position().as_secs_f32() / duration).clamp(0.0, 1.0);
        painter.rect_filled(
            Rect::from_min_max(pos2(bar.min.x, bar.min.y + 4.0), pos2(bar.min.x + bar.width() * fraction, bar.max.y - 4.0)),
            3.0,
            theme::ACCENT,
        );
        painter.circle_filled(pos2(bar.min.x + bar.width() * fraction, bar.center().y), 6.0, theme::CURSOR);
        if (bar_response.drag_stopped() || bar_response.clicked())
            && let Some(pointer) = bar_response.interact_pointer_pos()
        {
            let target = ((pointer.x - bar.min.x) / bar.width()).clamp(0.0, 1.0);
            self.seek(self.info.duration.mul_f32(target));
        }

        let (rect, _) = ui.allocate_exact_size(ui.available_size().max(vec2(64.0, 64.0)), Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, Color32::BLACK);
        if let Some(texture) = &self.texture {
            let frame_size = vec2(self.size.0 as f32, self.size.1 as f32);
            let scale = (rect.width() / frame_size.x).min(rect.height() / frame_size.y);
            let drawn = Rect::from_center_size(rect.center(), frame_size * scale);
            painter.image(texture.id(), drawn, Rect::from_min_max(Pos2::ZERO, pos2(1.0, 1.0)), Color32::WHITE);
        } else {
            painter.text(rect.center(), egui::Align2::CENTER_CENTER, "Decoding…", egui::FontId::proportional(14.0), theme::TEXT_DIM);
        }
        if self.playing || self.texture.is_none() || self.audio_pending.is_some() {
            ui.ctx().request_repaint_after(Duration::from_secs_f64(1.0 / (self.info.fps * 2.0).max(10.0)));
        }
    }
}

impl Drop for VideoView {
    fn drop(&mut self) {
        self.stream = None;
        std::fs::remove_file(&self.path).ok();
    }
}
