//! Raw elementary media streams: audio and video without a container.
//!
//! * MPEG audio (MP1/MP2/MP3) frames, chained by the frame length their
//!   headers imply; at least [`MIN_FRAMES`] in a row.
//! * AAC in ADTS frames, chained by the header's `frame_length` field.
//! * H.264 and H.265 Annex B byte streams: start codes followed by NAL unit
//!   headers of plausible types, with parameter sets.
//! * Raw 16-bit PCM audio: long runs of smooth samples that swing both ways
//!   about zero, with a guess at mono or interleaved stereo.
//!
//! MPEG transport streams are not detected here: the signature catalogue
//! already has them (`media/mpeg-ts`) and [`crate::media`] opens them.
//!
//! Scanning is linear in the window size; frame chains only start at sync
//! words and each byte is part of at most one chain.

use crate::plugin::{Category, Detector, Field, Finding, ScanContext};

/// Fewest consecutive frames that count as an audio stream.
pub const MIN_FRAMES: usize = 3;
/// NAL units needed for an Annex B stream that has no parameter sets in view.
pub const MIN_NALS_WITHOUT_PARAMETERS: usize = 16;
/// Bytes per block in the PCM scan.
pub const PCM_BLOCK: usize = 4096;
/// Consecutive smooth blocks needed for a PCM run (32 KiB).
pub const MIN_PCM_BLOCKS: usize = 8;
/// Sample rate assumed when PCM is wrapped as WAV to be played.
pub const ASSUMED_SAMPLE_RATE: u32 = 44_100;

/// Mean sample magnitude below which a block is silence or padding.
const PCM_MIN_LEVEL: f64 = 256.0;
/// Mean step between samples relative to the mean magnitude, above which
/// the signal is too rough to be sampled sound.
const PCM_MAX_ROUGHNESS: f64 = 0.5;
/// Share of positive samples allowed: sound swings both ways about zero.
const PCM_SIGN_BALANCE: std::ops::RangeInclusive<f64> = 0.25..=0.75;
/// Stereo when the lag-2 step is this much smaller than the lag-1 step.
const STEREO_STEP_RATIO: f64 = 0.8;
/// Channels count as identical when their difference is this small relative to the level.
const IDENTICAL_CHANNELS: f64 = 0.01;
/// Payload bytes of an H.264/H.265 SPS read to report profile and level.
const SPS_PREFIX: usize = 24;

/// What kind of stream a run holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StreamKind {
    MpegAudio,
    Adts,
    H264,
    H265,
    Pcm,
}

impl StreamKind {
    pub fn label(self) -> &'static str {
        match self {
            StreamKind::MpegAudio => "MPEG audio",
            StreamKind::Adts => "AAC (ADTS)",
            StreamKind::H264 => "H.264 video",
            StreamKind::H265 => "H.265 video",
            StreamKind::Pcm => "PCM audio",
        }
    }

    pub fn is_audio(self) -> bool {
        matches!(self, StreamKind::MpegAudio | StreamKind::Adts | StreamKind::Pcm)
    }

    /// Finding category: video is drawn as an image, audio as an encoding.
    pub fn category(self) -> Category {
        if self.is_audio() { Category::Encoding } else { Category::Image }
    }

    fn id(self) -> &'static str {
        match self {
            StreamKind::MpegAudio => "media:mpeg-audio",
            StreamKind::Adts => "media:aac-adts",
            StreamKind::H264 => "media:h264",
            StreamKind::H265 => "media:h265",
            StreamKind::Pcm => "media:pcm",
        }
    }
}

/// Facts about a PCM run needed to play it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcmLayout {
    pub big_endian: bool,
    pub channels: u16,
}

/// A run of one elementary stream. Offsets are relative to the scanned bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct StreamRun {
    pub kind: StreamKind,
    pub start: usize,
    pub len: usize,
    /// Frames, NAL units or 16-bit samples.
    pub units: usize,
    pub title: String,
    pub detail: String,
    /// The first frame or parameter-set header, offsets relative to the scan.
    pub fields: Vec<Field>,
    pub confidence: f32,
    /// Set for PCM runs.
    pub pcm: Option<PcmLayout>,
    /// Format name [`crate::media`] and the player know, when the run can be
    /// played as it is ("MP3", "AAC (ADTS)"); PCM is played as "WAV" after
    /// [`wav_from_pcm`].
    pub playable_as: Option<&'static str>,
}

impl StreamRun {
    pub fn end(&self) -> usize {
        self.start + self.len
    }

    /// A finding for this run, with offsets moved by `base`.
    pub fn to_finding(&self, source: &str, base: usize) -> Finding {
        Finding::new(self.kind.id(), source, self.kind.category(), base + self.start, self.len)
            .title(self.title.clone())
            .detail(self.detail.clone())
            .confidence(self.confidence)
            .fields(self.fields.iter().map(|field| shift_field(field, base)).collect())
    }
}

fn shift_field(field: &Field, base: usize) -> Field {
    Field::new(field.name.clone(), field.offset + base, field.len, field.value.clone()).with_children(field.children.iter().map(|child| shift_field(child, base)).collect())
}

/// Find every elementary stream in `bytes`, ordered by start.
pub fn find_streams(bytes: &[u8]) -> Vec<StreamRun> {
    let mut runs = Vec::new();
    runs.extend(find_mpeg_audio(bytes));
    runs.extend(find_adts(bytes));
    runs.extend(find_annex_b(bytes, VideoCodec::H264));
    runs.extend(find_annex_b(bytes, VideoCodec::H265));
    runs.extend(find_pcm(bytes));
    runs.sort_by_key(|run| (run.start, run.len));
    runs
}

/// The detector for the plugin registry.
pub struct ElementaryStreamDetector;

impl Detector for ElementaryStreamDetector {
    fn id(&self) -> &str {
        "builtin.elementary_streams"
    }

    fn name(&self) -> &str {
        "Raw media streams"
    }

    fn categories(&self) -> Vec<Category> {
        vec![Category::Encoding, Category::Image]
    }

    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        find_streams(window).iter().map(|run| run.to_finding(self.id(), context.base)).collect()
    }
}

// ---------------------------------------------------------------------------
// Frame chains (MPEG audio and ADTS)
// ---------------------------------------------------------------------------

/// Follow frames from `start` while `parse` accepts each header and it is
/// `compatible` with the first; returns the headers and the chain's end.
fn follow_chain<H>(bytes: &[u8], start: usize, parse: impl Fn(&[u8]) -> Option<H>, frame_len: impl Fn(&H) -> usize, compatible: impl Fn(&H, &H) -> bool) -> (Vec<H>, usize) {
    let mut headers: Vec<H> = Vec::new();
    let mut position = start;
    while let Some(header) = bytes.get(position..).and_then(&parse) {
        let len = frame_len(&header);
        if len == 0 || position + len > bytes.len() || headers.first().is_some_and(|first| !compatible(first, &header)) {
            break;
        }
        position += len;
        headers.push(header);
    }
    (headers, position)
}

/// Scan for frame chains: at each offset try a chain, keep it when it has
/// [`MIN_FRAMES`] frames, and continue after it.
fn find_chains<H>(bytes: &[u8], parse: impl Fn(&[u8]) -> Option<H>, frame_len: impl Fn(&H) -> usize, compatible: impl Fn(&H, &H) -> bool, mut build: impl FnMut(usize, usize, Vec<H>) -> StreamRun) -> Vec<StreamRun> {
    let mut runs = Vec::new();
    let mut offset = 0;
    while offset + 1 < bytes.len() {
        if bytes[offset] != 0xFF {
            offset += 1;
            continue;
        }
        let (headers, end) = follow_chain(bytes, offset, &parse, &frame_len, &compatible);
        if headers.len() >= MIN_FRAMES {
            runs.push(build(offset, end, headers));
            offset = end;
        } else {
            offset += 1;
        }
    }
    runs
}

// ---------------------------------------------------------------------------
// MPEG audio
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MpegVersion {
    V1,
    V2,
    V25,
}

impl MpegVersion {
    fn label(self) -> &'static str {
        match self {
            MpegVersion::V1 => "MPEG-1",
            MpegVersion::V2 => "MPEG-2",
            MpegVersion::V25 => "MPEG-2.5",
        }
    }
}

/// A decoded MPEG audio frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MpegHeader {
    version: MpegVersion,
    /// 1, 2 or 3.
    layer: u8,
    bitrate_kbps: u32,
    sample_rate: u32,
    padding: bool,
    protected: bool,
    channel_mode: u8,
    frame_len: usize,
}

const MPEG1_L1_KBPS: [u32; 14] = [32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448];
const MPEG1_L2_KBPS: [u32; 14] = [32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384];
const MPEG1_L3_KBPS: [u32; 14] = [32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320];
const MPEG2_L1_KBPS: [u32; 14] = [32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256];
const MPEG2_L23_KBPS: [u32; 14] = [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
const MPEG_RESERVED_EMPHASIS: u8 = 2;
const CHANNEL_MODES: [&str; 4] = ["stereo", "joint stereo", "dual channel", "mono"];

fn parse_mpeg_header(bytes: &[u8]) -> Option<MpegHeader> {
    let header: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    if header[0] != 0xFF || header[1] & 0xE0 != 0xE0 {
        return None;
    }
    let version = match (header[1] >> 3) & 3 {
        0 => MpegVersion::V25,
        2 => MpegVersion::V2,
        3 => MpegVersion::V1,
        _ => return None,
    };
    let layer = match (header[1] >> 1) & 3 {
        1 => 3,
        2 => 2,
        3 => 1,
        _ => return None,
    };
    let bitrate_index = (header[2] >> 4) as usize;
    let rate_index = ((header[2] >> 2) & 3) as usize;
    if bitrate_index == 0 || bitrate_index == 15 || rate_index == 3 || header[3] & 3 == MPEG_RESERVED_EMPHASIS {
        return None;
    }
    let table = match (version, layer) {
        (MpegVersion::V1, 1) => &MPEG1_L1_KBPS,
        (MpegVersion::V1, 2) => &MPEG1_L2_KBPS,
        (MpegVersion::V1, _) => &MPEG1_L3_KBPS,
        (_, 1) => &MPEG2_L1_KBPS,
        _ => &MPEG2_L23_KBPS,
    };
    let bitrate_kbps = table[bitrate_index - 1];
    let base_rate = [44_100, 48_000, 32_000][rate_index];
    let sample_rate = match version {
        MpegVersion::V1 => base_rate,
        MpegVersion::V2 => base_rate / 2,
        MpegVersion::V25 => base_rate / 4,
    };
    let padding = (header[2] >> 1) & 1 == 1;
    let bitrate = bitrate_kbps * 1000;
    let frame_len = match layer {
        1 => ((12 * bitrate / sample_rate) + padding as u32) * 4,
        3 if version != MpegVersion::V1 => 72 * bitrate / sample_rate + padding as u32,
        _ => 144 * bitrate / sample_rate + padding as u32,
    } as usize;
    Some(MpegHeader { version, layer, bitrate_kbps, sample_rate, padding, protected: header[1] & 1 == 0, channel_mode: header[3] >> 6, frame_len })
}

fn mpeg_header_fields(header: &MpegHeader, offset: usize) -> Field {
    Field::new("First frame header", offset, 4, format!("{} Layer {}", header.version.label(), roman(header.layer))).with_children(vec![
        Field::new("Sync", offset, 2, "0xFFE (11 bits)"),
        Field::new("Version", offset + 1, 1, header.version.label()),
        Field::new("Layer", offset + 1, 1, roman(header.layer)),
        Field::new("CRC protected", offset + 1, 1, if header.protected { "yes" } else { "no" }),
        Field::new("Bitrate", offset + 2, 1, format!("{} kbit/s", header.bitrate_kbps)),
        Field::new("Sample rate", offset + 2, 1, format!("{} Hz", header.sample_rate)),
        Field::new("Padding", offset + 2, 1, if header.padding { "yes" } else { "no" }),
        Field::new("Channel mode", offset + 3, 1, CHANNEL_MODES[header.channel_mode as usize & 3]),
        Field::new("Frame length", offset, header.frame_len, format!("{} bytes", header.frame_len)),
    ])
}

fn roman(layer: u8) -> &'static str {
    match layer {
        1 => "I",
        2 => "II",
        _ => "III",
    }
}

fn khz(sample_rate: u32) -> String {
    let khz = sample_rate as f64 / 1000.0;
    if sample_rate.is_multiple_of(1000) { format!("{khz:.0} kHz") } else { format!("{khz:.1} kHz") }
}

fn find_mpeg_audio(bytes: &[u8]) -> Vec<StreamRun> {
    let compatible = |first: &MpegHeader, next: &MpegHeader| first.version == next.version && first.layer == next.layer && first.sample_rate == next.sample_rate;
    find_chains(bytes, parse_mpeg_header, |header| header.frame_len, compatible, |start, end, headers| {
        let first = headers[0];
        let constant = headers.iter().all(|header| header.bitrate_kbps == first.bitrate_kbps);
        let bitrate = if constant {
            format!("{} kbit/s", first.bitrate_kbps)
        } else {
            let mean = headers.iter().map(|header| header.bitrate_kbps as u64).sum::<u64>() / headers.len() as u64;
            format!("VBR ~{mean} kbit/s")
        };
        let name = match first.layer {
            3 => "MP3",
            2 => "MP2",
            _ => "MP1",
        };
        let samples_per_frame = match (first.layer, first.version) {
            (1, _) => 384,
            (3, MpegVersion::V2 | MpegVersion::V25) => 576,
            _ => 1152,
        };
        let seconds = headers.len() as f64 * samples_per_frame as f64 / first.sample_rate as f64;
        StreamRun {
            kind: StreamKind::MpegAudio,
            start,
            len: end - start,
            units: headers.len(),
            title: format!("{name} audio, {bitrate}, {}, {} frames", khz(first.sample_rate), headers.len()),
            detail: format!("{} Layer {}, {}, about {seconds:.1} s", first.version.label(), roman(first.layer), CHANNEL_MODES[first.channel_mode as usize & 3]),
            fields: vec![mpeg_header_fields(&first, start)],
            confidence: chain_confidence(headers.len()),
            pcm: None,
            playable_as: (first.layer == 3).then_some("MP3"),
        }
    })
}

/// Confidence grows with the number of chained frames.
fn chain_confidence(frames: usize) -> f32 {
    (0.6 + 0.04 * frames as f32).min(0.98)
}

// ---------------------------------------------------------------------------
// AAC ADTS
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AdtsHeader {
    mpeg2: bool,
    protected: bool,
    profile: u8,
    rate_index: u8,
    channels: u8,
    frame_len: usize,
}

const ADTS_SAMPLE_RATES: [u32; 13] = [96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000, 7_350];
const ADTS_PROFILES: [&str; 4] = ["Main", "LC", "SSR", "LTP"];
const ADTS_HEADER_LEN: usize = 7;
const ADTS_CRC_LEN: usize = 2;
const AAC_SAMPLES_PER_FRAME: f64 = 1024.0;

fn parse_adts_header(bytes: &[u8]) -> Option<AdtsHeader> {
    let header: [u8; 7] = bytes.get(..ADTS_HEADER_LEN)?.try_into().ok()?;
    // 12-bit sync, then the layer field, which must be 0.
    if header[0] != 0xFF || header[1] & 0xF6 != 0xF0 {
        return None;
    }
    let rate_index = (header[2] >> 2) & 0x0F;
    if rate_index as usize >= ADTS_SAMPLE_RATES.len() {
        return None;
    }
    let protected = header[1] & 1 == 0;
    let frame_len = (((header[3] & 3) as usize) << 11) | ((header[4] as usize) << 3) | ((header[5] >> 5) as usize);
    let minimum = ADTS_HEADER_LEN + if protected { ADTS_CRC_LEN } else { 0 };
    if frame_len <= minimum {
        return None;
    }
    Some(AdtsHeader {
        mpeg2: header[1] & 0x08 != 0,
        protected,
        profile: header[2] >> 6,
        rate_index,
        channels: ((header[2] & 1) << 2) | (header[3] >> 6),
        frame_len,
    })
}

fn find_adts(bytes: &[u8]) -> Vec<StreamRun> {
    let compatible = |first: &AdtsHeader, next: &AdtsHeader| first.rate_index == next.rate_index && first.profile == next.profile && first.channels == next.channels;
    find_chains(bytes, parse_adts_header, |header| header.frame_len, compatible, |start, end, headers| {
        let first = headers[0];
        let sample_rate = ADTS_SAMPLE_RATES[first.rate_index as usize];
        let seconds = headers.len() as f64 * AAC_SAMPLES_PER_FRAME / sample_rate as f64;
        let kbps = ((end - start) as f64 * 8.0 / seconds.max(f64::EPSILON) / 1000.0).round();
        let channels = match first.channels {
            0 => "channels in stream".to_string(),
            1 => "mono".to_string(),
            2 => "stereo".to_string(),
            count => format!("{count} channels"),
        };
        let profile = ADTS_PROFILES[first.profile as usize & 3];
        let fields = vec![Field::new("First frame header", start, ADTS_HEADER_LEN, format!("ADTS, AAC {profile}")).with_children(vec![
            Field::new("Sync", start, 2, "0xFFF (12 bits)"),
            Field::new("MPEG version", start + 1, 1, if first.mpeg2 { "MPEG-2" } else { "MPEG-4" }),
            Field::new("CRC protected", start + 1, 1, if first.protected { "yes" } else { "no" }),
            Field::new("Profile", start + 2, 1, profile),
            Field::new("Sample rate", start + 2, 1, format!("{sample_rate} Hz")),
            Field::new("Channels", start + 2, 2, channels.clone()),
            Field::new("Frame length", start + 3, 3, format!("{} bytes", first.frame_len)),
        ])];
        StreamRun {
            kind: StreamKind::Adts,
            start,
            len: end - start,
            units: headers.len(),
            title: format!("AAC {profile} audio (ADTS), ~{kbps:.0} kbit/s, {}, {} frames", khz(sample_rate), headers.len()),
            detail: format!("{channels}, about {seconds:.1} s"),
            fields,
            confidence: chain_confidence(headers.len()),
            pcm: None,
            playable_as: Some("AAC (ADTS)"),
        }
    })
}

// ---------------------------------------------------------------------------
// H.264 / H.265 Annex B
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VideoCodec {
    H264,
    H265,
}

/// One NAL unit: where its start code begins, where its header is, where
/// its payload ends, and its type.
#[derive(Clone, Copy, Debug)]
struct Nal {
    start_code: usize,
    header: usize,
    end: usize,
    nal_type: u8,
}

/// The NAL type if `header` is a plausible NAL unit header for `codec`.
fn nal_type(codec: VideoCodec, header: &[u8]) -> Option<u8> {
    let first = *header.first()?;
    if first & 0x80 != 0 {
        return None;
    }
    match codec {
        VideoCodec::H264 => {
            let ref_idc = (first >> 5) & 3;
            let nal_type = first & 0x1F;
            let valid = match nal_type {
                // IDR slices and parameter sets are always reference data.
                5 | 7 | 8 => ref_idc != 0,
                // SEI, delimiters and filler never are.
                6 | 9..=12 => ref_idc == 0,
                1..=4 | 13..=15 | 19 | 20 => true,
                _ => false,
            };
            valid.then_some(nal_type)
        }
        VideoCodec::H265 => {
            let second = *header.get(1)?;
            let nal_type = (first >> 1) & 0x3F;
            let layer_id = ((first & 1) << 5) | (second >> 3);
            let temporal_id_plus1 = second & 7;
            let irap = (16..=23).contains(&nal_type);
            let known = matches!(nal_type, 0..=9 | 16..=21 | 32..=40);
            (known && layer_id == 0 && temporal_id_plus1 >= 1 && (!irap || temporal_id_plus1 == 1)).then_some(nal_type)
        }
    }
}

/// End of a NAL unit's payload: the first `00 00 0x` with x ≤ 2, which
/// emulation prevention keeps out of every payload.
fn nal_payload_end(bytes: &[u8], from: usize) -> usize {
    let mut index = from;
    while index + 2 < bytes.len() {
        if bytes[index + 2] > 2 {
            index += 3;
        } else if bytes[index] == 0 && bytes[index + 1] == 0 {
            return index;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

/// The header position of the start code that follows `end` (skipping
/// trailing zero bytes), if the stream continues there.
fn next_start_code(bytes: &[u8], end: usize) -> Option<usize> {
    let mut index = end;
    while index < bytes.len() && bytes[index] == 0 {
        index += 1;
    }
    (index - end >= 2 && bytes.get(index) == Some(&1)).then_some(index + 1)
}

/// Find the next `00 00 01` at or after `from`; returns the header position.
fn find_start_code(bytes: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index + 2 < bytes.len() {
        if bytes[index + 2] > 1 {
            index += 3;
        } else if bytes[index + 2] == 1 && bytes[index] == 0 && bytes[index + 1] == 0 {
            return Some(index + 3);
        } else {
            index += 1;
        }
    }
    None
}

/// Where the start code before the header at `header` begins (3 or 4 bytes).
fn start_code_begin(bytes: &[u8], header: usize) -> usize {
    if header >= 4 && bytes[header - 4] == 0 { header - 4 } else { header - 3 }
}

/// NAL units chained from the header at `header`, until a start code is
/// followed by an implausible header or the stream stops.
fn follow_nals(bytes: &[u8], codec: VideoCodec, header: usize) -> Vec<Nal> {
    let header_len = if codec == VideoCodec::H264 { 1 } else { 2 };
    let mut nals = Vec::new();
    let mut position = Some(header);
    while let Some(header) = position {
        let Some(nal_type) = bytes.get(header..).and_then(|rest| nal_type(codec, rest)) else { break };
        let end = nal_payload_end(bytes, header + header_len);
        nals.push(Nal { start_code: start_code_begin(bytes, header), header, end, nal_type });
        position = next_start_code(bytes, end);
    }
    nals
}

fn find_annex_b(bytes: &[u8], codec: VideoCodec) -> Vec<StreamRun> {
    let mut runs = Vec::new();
    let mut search_from = 0;
    while let Some(header) = find_start_code(bytes, search_from) {
        let nals = follow_nals(bytes, codec, header);
        let next = nals.last().map_or(header, |nal| nal.end.max(header));
        if let Some(run) = annex_b_run(bytes, codec, &nals) {
            runs.push(run);
        }
        search_from = next.max(header);
    }
    runs
}

/// Remove emulation-prevention bytes (`00 00 03` → `00 00`) from up to
/// `limit` output bytes of a NAL payload.
fn unescape_rbsp(payload: &[u8], limit: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(limit.min(payload.len()));
    let mut zeros = 0;
    for &byte in payload {
        if output.len() >= limit {
            break;
        }
        if zeros >= 2 && byte == 3 {
            zeros = 0;
            continue;
        }
        zeros = if byte == 0 { zeros + 1 } else { 0 };
        output.push(byte);
    }
    output
}

fn h264_profile_name(profile_idc: u8) -> Option<&'static str> {
    Some(match profile_idc {
        66 => "Baseline",
        77 => "Main",
        88 => "Extended",
        100 => "High",
        110 => "High 10",
        122 => "High 4:2:2",
        244 => "High 4:4:4",
        44 => "CAVLC 4:4:4",
        83 | 86 => "Scalable",
        118 | 128 => "Multiview",
        _ => return None,
    })
}

fn h265_profile_name(profile_idc: u8) -> &'static str {
    match profile_idc {
        1 => "Main",
        2 => "Main 10",
        3 => "Main Still Picture",
        4 => "Range extensions",
        _ => "other",
    }
}

/// Profile and level from an SPS, if it parses: H.264 SPS starts with
/// profile_idc, constraint flags, level_idc; H.265 SPS has a
/// profile_tier_level after one byte of ids.
fn sps_summary(bytes: &[u8], codec: VideoCodec, nal: &Nal) -> Option<(String, Vec<Field>)> {
    let header_len = if codec == VideoCodec::H264 { 1 } else { 2 };
    let payload = unescape_rbsp(bytes.get(nal.header + header_len..nal.end)?, SPS_PREFIX);
    match codec {
        VideoCodec::H264 => {
            let profile_idc = *payload.first()?;
            let level_idc = *payload.get(2)?;
            let profile = h264_profile_name(profile_idc)?;
            let level = format!("{:.1}", level_idc as f32 / 10.0);
            let fields = vec![Field::new("SPS", nal.header, nal.end - nal.header, format!("{profile} profile, level {level}")).with_children(vec![
                Field::new("NAL header", nal.header, 1, "type 7 (SPS)"),
                Field::new("profile_idc", nal.header + 1, 1, format!("{profile_idc} ({profile})")),
                Field::new("constraint flags", nal.header + 2, 1, format!("{:#04x}", payload.get(1).copied().unwrap_or(0))),
                Field::new("level_idc", nal.header + 3, 1, format!("{level_idc} (level {level})")),
            ])];
            Some((format!("{profile} profile, level {level}"), fields))
        }
        VideoCodec::H265 => {
            const LEVEL_OFFSET: usize = 12;
            let profile_idc = payload.get(1)? & 0x1F;
            let tier = if payload.get(1)? & 0x20 != 0 { "High tier" } else { "Main tier" };
            let level_idc = *payload.get(LEVEL_OFFSET)?;
            let profile = h265_profile_name(profile_idc);
            let level = format!("{:.1}", level_idc as f32 / 30.0);
            let fields = vec![Field::new("SPS", nal.header, nal.end - nal.header, format!("{profile} profile, {tier}, level {level}")).with_children(vec![
                Field::new("NAL header", nal.header, 2, "type 33 (SPS)"),
                Field::new("general_profile_idc", nal.header + 3, 1, format!("{profile_idc} ({profile})")),
            ])];
            Some((format!("{profile} profile, {tier}, level {level}"), fields))
        }
    }
}

/// A run when the NAL units make a plausible stream: parameter sets and a
/// slice, or many slices.
fn annex_b_run(bytes: &[u8], codec: VideoCodec, nals: &[Nal]) -> Option<StreamRun> {
    let has = |wanted: &[u8]| nals.iter().any(|nal| wanted.contains(&nal.nal_type));
    let (sps, pps, vps, slices, keyframes): (u8, u8, Option<u8>, &[u8], &[u8]) = match codec {
        VideoCodec::H264 => (7, 8, None, &[1, 5], &[5]),
        VideoCodec::H265 => (33, 34, Some(32), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 18, 19, 20, 21], &[16, 17, 18, 19, 20, 21]),
    };
    let parameter_sets = has(&[sps]) && has(&[pps]) && vps.is_none_or(|vps| has(&[vps]));
    let slice_count = nals.iter().filter(|nal| slices.contains(&nal.nal_type)).count();
    let qualifies = (parameter_sets && slice_count > 0) || slice_count >= MIN_NALS_WITHOUT_PARAMETERS;
    if !qualifies {
        return None;
    }
    let sps_nal = nals.iter().find(|nal| nal.nal_type == sps);
    let summary = sps_nal.and_then(|nal| sps_summary(bytes, codec, nal));
    if codec == VideoCodec::H264 && sps_nal.is_some() && summary.is_none() {
        // An SPS with an unknown profile: more likely noise than video.
        return None;
    }
    let (first, last) = (nals.first()?, nals.last()?);
    let keyframe_count = nals.iter().filter(|nal| keyframes.contains(&nal.nal_type)).count();
    let name = if codec == VideoCodec::H264 { "H.264" } else { "H.265" };
    let title = match &summary {
        Some((profile, _)) => format!("{name} video ({profile}), {} NAL units", nals.len()),
        None => format!("{name} video, {} NAL units", nals.len()),
    };
    let detail = format!("Annex B byte stream: {slice_count} slices, {keyframe_count} keyframe (IRAP/IDR) slices{}", if parameter_sets { ", parameter sets present" } else { ", no parameter sets in view" });
    let kind = if codec == VideoCodec::H264 { StreamKind::H264 } else { StreamKind::H265 };
    Some(StreamRun {
        kind,
        start: first.start_code,
        len: last.end - first.start_code,
        units: nals.len(),
        title,
        detail,
        fields: summary.map(|(_, fields)| fields).unwrap_or_default(),
        confidence: if parameter_sets { 0.9 } else { 0.6 },
        pcm: None,
        playable_as: None,
    })
}

// ---------------------------------------------------------------------------
// PCM
// ---------------------------------------------------------------------------

/// Measurements of one block read as 16-bit samples.
#[derive(Clone, Copy, Debug)]
struct PcmBlock {
    big_endian: bool,
    /// Mean step at lag 1 and lag 2, relative to the mean level.
    roughness_lag1: f64,
    roughness_lag2: f64,
    /// Mean |left − right| of sample pairs, relative to the level.
    channel_difference: f64,
}

fn samples(block: &[u8], big_endian: bool) -> Vec<f64> {
    block.as_chunks::<2>().0.iter().map(|pair| if big_endian { i16::from_be_bytes(*pair) } else { i16::from_le_bytes(*pair) } as f64).collect()
}

fn mean_step(samples: &[f64], lag: usize) -> f64 {
    let steps = samples.len().saturating_sub(lag).max(1);
    samples.iter().zip(samples.iter().skip(lag)).map(|(a, b)| (a - b).abs()).sum::<f64>() / steps as f64
}

/// The block as PCM in one byte order, if it looks like sampled sound.
fn pcm_block_as(block: &[u8], big_endian: bool) -> Option<PcmBlock> {
    let samples = samples(block, big_endian);
    if samples.len() < 64 {
        return None;
    }
    let level = samples.iter().map(|sample| sample.abs()).sum::<f64>() / samples.len() as f64;
    if level < PCM_MIN_LEVEL {
        return None;
    }
    let roughness_lag1 = mean_step(&samples, 1) / level;
    let roughness_lag2 = mean_step(&samples, 2) / level;
    let non_zero = samples.iter().filter(|&&sample| sample != 0.0).count().max(1) as f64;
    let positive = samples.iter().filter(|&&sample| sample > 0.0).count() as f64 / non_zero;
    if roughness_lag1.min(roughness_lag2) > PCM_MAX_ROUGHNESS || !PCM_SIGN_BALANCE.contains(&positive) {
        return None;
    }
    let pairs = samples.as_chunks::<2>().0;
    let channel_difference = pairs.iter().map(|[left, right]| (left - right).abs()).sum::<f64>() / pairs.len().max(1) as f64 / level;
    Some(PcmBlock { big_endian, roughness_lag1, roughness_lag2, channel_difference })
}

/// The smoother of the two byte orders, if either looks like sound.
fn pcm_block(block: &[u8]) -> Option<PcmBlock> {
    let roughness = |block: &PcmBlock| block.roughness_lag1.min(block.roughness_lag2);
    match (pcm_block_as(block, false), pcm_block_as(block, true)) {
        (Some(little), Some(big)) => Some(if roughness(&big) < roughness(&little) { big } else { little }),
        (little, big) => little.or(big),
    }
}

fn find_pcm(bytes: &[u8]) -> Vec<StreamRun> {
    let blocks: Vec<Option<PcmBlock>> = bytes.as_chunks::<PCM_BLOCK>().0.iter().map(|block| pcm_block(block)).collect();
    let mut runs = Vec::new();
    let mut index = 0;
    while index < blocks.len() {
        let Some(first) = blocks[index] else {
            index += 1;
            continue;
        };
        let run_end = (index..blocks.len()).find(|&next| blocks[next].is_none_or(|block| block.big_endian != first.big_endian)).unwrap_or(blocks.len());
        if run_end - index >= MIN_PCM_BLOCKS {
            runs.push(pcm_run(&blocks[index..run_end], index * PCM_BLOCK));
        }
        index = run_end;
    }
    runs
}

fn pcm_run(blocks: &[Option<PcmBlock>], start: usize) -> StreamRun {
    let measured: Vec<PcmBlock> = blocks.iter().flatten().copied().collect();
    let count = measured.len() as f64;
    let lag1 = measured.iter().map(|block| block.roughness_lag1).sum::<f64>() / count;
    let lag2 = measured.iter().map(|block| block.roughness_lag2).sum::<f64>() / count;
    let channel_difference = measured.iter().map(|block| block.channel_difference).sum::<f64>() / count;
    let big_endian = measured[0].big_endian;
    let (channels, channel_note) = if channel_difference < IDENTICAL_CHANNELS {
        (2, "likely stereo with identical channels".to_string())
    } else if lag2 < lag1 * STEREO_STEP_RATIO {
        (2, format!("likely interleaved stereo (step to the next sample of the same channel is {:.0}% of the step to the neighbour)", lag2 / lag1 * 100.0))
    } else {
        (1, "likely mono".to_string())
    };
    let len = blocks.len() * PCM_BLOCK;
    let order = if big_endian { "big-endian" } else { "little-endian" };
    let roughness = lag1.min(lag2);
    StreamRun {
        kind: StreamKind::Pcm,
        start,
        len,
        units: len / 2,
        title: format!("PCM audio, 16-bit {order}, {}, {} KiB", if channels == 2 { "stereo" } else { "mono" }, len / 1024),
        detail: format!("{channel_note}; smooth samples (mean step {:.0}% of level) that swing both ways; sample rate unknown", roughness * 100.0),
        fields: Vec::new(),
        confidence: (0.55 + 0.4 * (1.0 - roughness / PCM_MAX_ROUGHNESS)) as f32,
        pcm: Some(PcmLayout { big_endian, channels }),
        playable_as: Some("WAV"),
    }
}

/// Wrap 16-bit PCM in a WAV header so the player can open it; big-endian
/// samples are swapped to little-endian. An odd trailing byte is dropped.
pub fn wav_from_pcm(pcm: &[u8], layout: PcmLayout, sample_rate: u32) -> Vec<u8> {
    const BITS_PER_SAMPLE: u16 = 16;
    const HEADER_LEN: usize = 44;
    const PCM_FORMAT_TAG: u16 = 1;
    let data_len = pcm.len() & !1;
    let channels = layout.channels.max(1);
    let block_align = channels * BITS_PER_SAMPLE / 8;
    let byte_rate = sample_rate * block_align as u32;
    let mut wav = Vec::with_capacity(HEADER_LEN + data_len);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&u32::try_from(36 + data_len).unwrap_or(u32::MAX).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&PCM_FORMAT_TAG.to_le_bytes());
    wav.extend_from_slice(&channels.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&block_align.to_le_bytes());
    wav.extend_from_slice(&BITS_PER_SAMPLE.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&u32::try_from(data_len).unwrap_or(u32::MAX).to_le_bytes());
    for pair in pcm[..data_len].as_chunks::<2>().0 {
        if layout.big_endian {
            wav.extend_from_slice(&[pair[1], pair[0]]);
        } else {
            wav.extend_from_slice(pair);
        }
    }
    wav
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MPEG-1 Layer III, 128 kbit/s, 44.1 kHz, no padding, joint stereo.
    const MP3_HEADER: [u8; 4] = [0xFF, 0xFB, 0x90, 0x44];
    const MP3_FRAME_LEN: usize = 417;

    fn mp3_frames(count: usize) -> Vec<u8> {
        let mut stream = Vec::new();
        for index in 0..count {
            stream.extend_from_slice(&MP3_HEADER);
            stream.extend((0..MP3_FRAME_LEN - 4).map(|byte| (byte * 7 + index) as u8 | 1));
        }
        stream
    }

    fn adts_frames(count: usize, frame_len: usize) -> Vec<u8> {
        let mut stream = Vec::new();
        for _ in 0..count {
            // MPEG-4, no CRC, AAC LC, 44.1 kHz (index 4), 2 channels.
            let header = [0xFF, 0xF1, 0x50, 0x80 | ((frame_len >> 11) & 3) as u8, ((frame_len >> 3) & 0xFF) as u8, (((frame_len & 7) << 5) | 0x1F) as u8, 0xFC];
            stream.extend_from_slice(&header);
            stream.extend(std::iter::repeat_n(0x21, frame_len - 7));
        }
        stream
    }

    fn nal(start_code: &[u8], header: &[u8], payload_len: usize) -> Vec<u8> {
        let mut unit = start_code.to_vec();
        unit.extend_from_slice(header);
        unit.extend((0..payload_len).map(|index| (index % 200) as u8 + 0x10));
        unit
    }

    fn sine_pcm(frequency: f64, seconds: f64, stereo: bool) -> Vec<u8> {
        let rate = 44_100.0;
        let mut pcm = Vec::new();
        for index in 0..(rate * seconds) as usize {
            let t = index as f64 / rate;
            let left = (10_000.0 * (2.0 * std::f64::consts::PI * frequency * t).sin()) as i16;
            pcm.extend_from_slice(&left.to_le_bytes());
            if stereo {
                let right = (8_000.0 * (2.0 * std::f64::consts::PI * frequency * 1.5 * t).cos()) as i16;
                pcm.extend_from_slice(&right.to_le_bytes());
            }
        }
        pcm
    }

    #[test]
    fn a_run_of_mp3_frames_is_found_with_its_bitrate_and_extent() {
        let mut data = vec![0x11; 100];
        data.extend(mp3_frames(213));
        data.extend(vec![0x22; 50]);
        let runs = find_streams(&data);
        let run = runs.iter().find(|run| run.kind == StreamKind::MpegAudio).expect("MP3 run");
        assert_eq!(run.start, 100);
        assert_eq!(run.len, 213 * MP3_FRAME_LEN);
        assert_eq!(run.title, "MP3 audio, 128 kbit/s, 44.1 kHz, 213 frames");
        assert_eq!(run.playable_as, Some("MP3"));
        assert_eq!(run.fields[0].offset, 100);
    }

    #[test]
    fn two_mp3_frames_are_not_enough_to_count_as_a_stream() {
        assert!(find_mpeg_audio(&mp3_frames(2)).is_empty());
    }

    #[test]
    fn a_chain_of_adts_frames_is_found_with_its_sample_rate() {
        let mut data = vec![0x00; 33];
        data.extend(adts_frames(10, 300));
        let runs = find_adts(&data);
        assert_eq!(runs.len(), 1);
        assert_eq!((runs[0].start, runs[0].len, runs[0].units), (33, 3000, 10));
        assert!(runs[0].title.contains("44.1 kHz"), "{}", runs[0].title);
        assert!(runs[0].title.contains("LC"));
    }

    #[test]
    fn an_h264_stream_of_sps_pps_and_idr_nal_units_is_found_with_its_profile() {
        let mut data = vec![0x55; 10];
        data.extend(nal(&[0, 0, 0, 1], &[0x67, 100, 0x00, 40], 12)); // SPS, High, level 4.0
        data.extend(nal(&[0, 0, 0, 1], &[0x68], 4)); // PPS
        data.extend(nal(&[0, 0, 1], &[0x65], 500)); // IDR slice
        data.extend(nal(&[0, 0, 1], &[0x41], 300)); // non-IDR slice
        let stream_end = data.len();
        data.extend([0, 0, 0, 0, 0xAB]);
        let runs = find_annex_b(&data, VideoCodec::H264);
        assert_eq!(runs.len(), 1, "{runs:?}");
        assert_eq!(runs[0].start, 10);
        assert_eq!(runs[0].end(), stream_end);
        assert_eq!(runs[0].units, 4);
        assert!(runs[0].title.contains("High profile, level 4.0"), "{}", runs[0].title);
        assert!(find_annex_b(&data, VideoCodec::H265).is_empty());
    }

    #[test]
    fn an_h265_stream_with_vps_sps_and_pps_is_found() {
        let mut data = Vec::new();
        data.extend(nal(&[0, 0, 0, 1], &[0x40, 0x01], 20)); // VPS
        // ids, profile (Main), compatibility and constraint flags with
        // emulation-prevention bytes, then level_idc 93 (level 3.1).
        let mut sps = vec![0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 93];
        sps.extend([0x12; 8]);
        data.extend(nal(&[0, 0, 0, 1], &[0x42, 0x01], 0));
        data.extend(&sps);
        data.extend(nal(&[0, 0, 0, 1], &[0x44, 0x01], 6)); // PPS
        data.extend(nal(&[0, 0, 1], &[0x26, 0x01], 400)); // IDR_W_RADL
        let runs = find_annex_b(&data, VideoCodec::H265);
        assert_eq!(runs.len(), 1, "{runs:?}");
        assert_eq!(runs[0].units, 4);
        assert!(runs[0].title.starts_with("H.265 video (Main profile"), "{}", runs[0].title);
        assert!(runs[0].title.contains("level 3.1"), "{}", runs[0].title);
    }

    #[test]
    fn scattered_start_codes_without_parameter_sets_are_ignored() {
        let mut data = Vec::new();
        for _ in 0..5 {
            data.extend(nal(&[0, 0, 1], &[0x41], 40));
            data.extend([0x00, 0x00, 0x02, 0x77]);
        }
        assert!(find_annex_b(&data, VideoCodec::H264).is_empty());
    }

    #[test]
    fn a_440_hz_pcm_sine_is_detected_as_mono_pcm() {
        let runs = find_pcm(&sine_pcm(440.0, 1.0, false));
        assert_eq!(runs.len(), 1);
        let layout = runs[0].pcm.unwrap();
        assert_eq!(layout, PcmLayout { big_endian: false, channels: 1 });
        assert!(runs[0].detail.contains("sample rate unknown"));
    }

    #[test]
    fn interleaved_stereo_pcm_is_reported_as_stereo() {
        let runs = find_pcm(&sine_pcm(300.0, 1.0, true));
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].pcm.unwrap().channels, 2, "{}", runs[0].detail);
    }

    #[test]
    fn big_endian_pcm_is_recognised_by_its_byte_order() {
        let swapped: Vec<u8> = sine_pcm(440.0, 1.0, false).as_chunks::<2>().0.iter().flat_map(|pair| [pair[1], pair[0]]).collect();
        let runs = find_pcm(&swapped);
        assert_eq!(runs.len(), 1);
        assert!(runs[0].pcm.unwrap().big_endian);
    }

    #[test]
    fn random_bytes_and_text_hold_no_streams() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let random: Vec<u8> = (0..256 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect();
        assert!(find_streams(&random).is_empty());
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(2000);
        assert!(find_streams(text.as_bytes()).is_empty());
    }

    #[test]
    fn arbitrary_short_inputs_do_not_panic() {
        for len in 0..64 {
            let bytes: Vec<u8> = (0..len).map(|index| [0x00, 0x01, 0xFF, 0xFB, 0x67][index % 5]).collect();
            let _ = find_streams(&bytes);
        }
    }

    #[test]
    fn the_detector_reports_findings_at_document_offsets() {
        let context = ScanContext { base: 0x1000, document_len: 0x100000, strides: Vec::new() };
        let findings = ElementaryStreamDetector.scan(&mp3_frames(5), &context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].start, 0x1000);
        assert_eq!(findings[0].fields[0].offset, 0x1000);
        assert_eq!(findings[0].category, Category::Encoding);
    }

    #[test]
    fn pcm_wrapped_as_wav_is_recognised_as_wav_media() {
        let wav = wav_from_pcm(&sine_pcm(440.0, 0.1, false), PcmLayout { big_endian: false, channels: 1 }, ASSUMED_SAMPLE_RATE);
        assert_eq!(crate::media::detect(&wav).map(|format| format.name), Some("WAV"));
        assert!(crate::media::analyse_audio(wav, 16).is_ok());
    }
}
