//! Compression detection and (de)compression of byte ranges.
//!
//! Streams are recognised by their headers and then *verified* by trial
//! decompression, so a highlight only says "zlib stream" when the bytes really
//! inflate. All codecs are pure Rust.

use std::io::{BufRead, Read, Write};
use std::sync::Arc;

use crate::plugin::{CodecKind, CodecPlugin, Decoded};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Codec {
    Zlib,
    Gzip,
    Deflate,
    Bzip2,
    Xz,
    Lzma,
    Zstd,
    Lz4,
}

impl Codec {
    /// Codecs with a recognisable header, in the order they are tested.
    pub const DETECTABLE: [Codec; 6] = [Codec::Gzip, Codec::Zlib, Codec::Bzip2, Codec::Xz, Codec::Zstd, Codec::Lz4];
    /// Codecs without a header that only a trial decode can find.
    pub const HEADERLESS: [Codec; 2] = [Codec::Deflate, Codec::Lzma];
    /// Codecs this module can also encode.
    pub const COMPRESSIBLE: [Codec; 5] = [Codec::Zlib, Codec::Gzip, Codec::Deflate, Codec::Bzip2, Codec::Lz4];

    pub fn label(self) -> &'static str {
        match self {
            Codec::Zlib => "zlib",
            Codec::Gzip => "gzip",
            Codec::Deflate => "raw deflate",
            Codec::Bzip2 => "bzip2",
            Codec::Xz => "xz",
            Codec::Lzma => "lzma",
            Codec::Zstd => "zstd",
            Codec::Lz4 => "LZ4 frame",
        }
    }

    pub fn from_name(name: &str) -> Option<Codec> {
        let name = name.to_ascii_lowercase();
        [Codec::Zlib, Codec::Gzip, Codec::Deflate, Codec::Bzip2, Codec::Xz, Codec::Lzma, Codec::Zstd, Codec::Lz4]
            .into_iter()
            .find(|codec| codec.label().to_ascii_lowercase().starts_with(&name))
    }
}

/// Result of decompressing from the start of a slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decompressed {
    pub codec: Codec,
    pub data: Vec<u8>,
    /// Input bytes the stream occupied.
    pub consumed: usize,
    /// Whether `consumed` is exact (headerless-aware decoders) or an estimate
    /// from a buffered reader (zstd, LZ4).
    pub consumed_exact: bool,
    /// The stream ended cleanly.
    pub complete: bool,
    /// Output was cut at the caller's limit.
    pub truncated: bool,
}

/// A verified stream found by scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub codec: Codec,
    /// Document offset of the first byte.
    pub start: usize,
    pub compressed_len: usize,
    pub decompressed_len: usize,
    pub complete: bool,
    pub truncated: bool,
}

/// Which codec, if any, the bytes at the start of `bytes` claim to be.
pub fn detect_header(bytes: &[u8]) -> Option<Codec> {
    if bytes.starts_with(&[0x1F, 0x8B, 0x08]) {
        return Some(Codec::Gzip);
    }
    if bytes.len() >= 2 && is_zlib_header(bytes[0], bytes[1]) {
        return Some(Codec::Zlib);
    }
    if bytes.len() >= 10 && bytes.starts_with(b"BZh") && bytes[3].is_ascii_digit() && &bytes[4..10] == b"\x31\x41\x59\x26\x53\x59" {
        return Some(Codec::Bzip2);
    }
    if bytes.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some(Codec::Xz);
    }
    if bytes.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(Codec::Zstd);
    }
    if bytes.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        return Some(Codec::Lz4);
    }
    None
}

/// RFC 1950: method 8, window ≤ 32 KiB, no preset dictionary, valid check bits.
fn is_zlib_header(cmf: u8, flg: u8) -> bool {
    cmf & 0x0F == 8 && cmf >> 4 <= 7 && flg & 0x20 == 0 && (cmf as u16 * 256 + flg as u16).is_multiple_of(31)
}

/// A slice reader that remembers how far it has been read.
struct Counting<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Read for Counting<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = out.len().min(self.data.len() - self.pos);
        out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl BufRead for Counting<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        Ok(&self.data[self.pos..])
    }

    fn consume(&mut self, amount: usize) {
        self.pos = (self.pos + amount).min(self.data.len());
    }
}

/// Pull up to `max_out` bytes from a decoder.
fn read_bounded(mut reader: impl Read, max_out: usize) -> Result<(Vec<u8>, bool, bool), String> {
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let want = chunk.len().min(max_out - out.len());
        if want == 0 {
            // Is there more? One extra byte tells us.
            let mut probe = [0u8; 1];
            return match reader.read(&mut probe) {
                Ok(0) => Ok((out, true, false)),
                Ok(_) => Ok((out, false, true)),
                Err(error) => Err(error.to_string()),
            };
        }
        match reader.read(&mut chunk[..want]) {
            Ok(0) => return Ok((out, true, false)),
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(error) => return Err(error.to_string()),
        }
    }
}

/// Decompress `input` with `codec`, producing at most `max_out` bytes.
pub fn decompress(codec: Codec, input: &[u8], max_out: usize) -> Result<Decompressed, String> {
    match codec {
        Codec::Zlib => inflate(input, true, max_out).map(|(data, consumed, complete, truncated)| Decompressed {
            codec,
            data,
            consumed,
            consumed_exact: true,
            complete,
            truncated,
        }),
        Codec::Deflate => inflate(input, false, max_out).map(|(data, consumed, complete, truncated)| Decompressed {
            codec,
            data,
            consumed,
            consumed_exact: true,
            complete,
            truncated,
        }),
        Codec::Gzip => {
            let header_len = gzip_header_len(input).ok_or("not a gzip header")?;
            let (data, consumed, complete, truncated) = inflate(&input[header_len..], false, max_out)?;
            // Trailer: CRC32 and ISIZE.
            let consumed = header_len + consumed + if complete { 8 } else { 0 };
            if complete && consumed > input.len() {
                return Err("gzip stream is missing its trailer".to_string());
            }
            Ok(Decompressed { codec, data, consumed, consumed_exact: true, complete, truncated })
        }
        Codec::Bzip2 => {
            let mut decoder = bzip2::Decompress::new(false);
            let mut out = Vec::new();
            let mut complete = false;
            let mut truncated = false;
            loop {
                let before_out = out.len();
                let in_pos = decoder.total_in() as usize;
                if out.capacity() == out.len() {
                    out.reserve(64 * 1024);
                }
                let status = decoder.decompress_vec(&input[in_pos..], &mut out).map_err(|e| e.to_string())?;
                if status == bzip2::Status::StreamEnd {
                    complete = true;
                }
                // A single call can decode a whole 900 KiB block, so apply the
                // limit before trusting "complete".
                if out.len() >= max_out {
                    truncated = out.len() > max_out || !complete;
                    out.truncate(max_out);
                    break;
                }
                if complete {
                    break;
                }
                if out.len() == before_out && decoder.total_in() as usize == in_pos {
                    return Err("bzip2 stream ended early".to_string());
                }
                if decoder.total_in() as usize >= input.len() && out.len() == before_out {
                    return Err("bzip2 stream ended early".to_string());
                }
            }
            Ok(Decompressed {
                codec,
                data: out,
                consumed: decoder.total_in() as usize,
                consumed_exact: true,
                complete,
                truncated,
            })
        }
        Codec::Xz | Codec::Lzma => {
            let mut reader = Counting { data: input, pos: 0 };
            let mut out = Vec::new();
            let mut sink = Bounded { out: &mut out, max_out, truncated: false };
            let result = if codec == Codec::Xz {
                lzma_rs::xz_decompress(&mut reader, &mut sink)
            } else {
                lzma_rs::lzma_decompress(&mut reader, &mut sink)
            };
            let truncated = sink.truncated;
            match result {
                Ok(()) => Ok(Decompressed {
                    codec,
                    data: out,
                    consumed: reader.pos,
                    consumed_exact: true,
                    complete: true,
                    truncated: false,
                }),
                Err(_) if truncated => Ok(Decompressed {
                    codec,
                    data: out,
                    consumed: reader.pos,
                    consumed_exact: false,
                    complete: false,
                    truncated: true,
                }),
                Err(error) => Err(error.to_string()),
            }
        }
        Codec::Zstd => {
            let mut reader = Counting { data: input, pos: 0 };
            let decoder = ruzstd::decoding::StreamingDecoder::new(&mut reader).map_err(|e| e.to_string())?;
            let (data, complete, truncated) = read_bounded(decoder, max_out)?;
            Ok(Decompressed { codec, data, consumed: reader.pos, consumed_exact: false, complete, truncated })
        }
        Codec::Lz4 => {
            let mut reader = Counting { data: input, pos: 0 };
            let decoder = lz4_flex::frame::FrameDecoder::new(&mut reader);
            let (data, complete, truncated) = read_bounded(decoder, max_out)?;
            Ok(Decompressed { codec, data, consumed: reader.pos, consumed_exact: false, complete, truncated })
        }
    }
}

/// A writer that stops accepting bytes after `max_out`, signalling an error so
/// streaming decoders bail out instead of inflating a bomb.
struct Bounded<'a> {
    out: &'a mut Vec<u8>,
    max_out: usize,
    truncated: bool,
}

impl Write for Bounded<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let room = self.max_out.saturating_sub(self.out.len());
        if room == 0 {
            self.truncated = true;
            return Err(std::io::Error::other("output limit reached"));
        }
        let n = bytes.len().min(room);
        self.out.extend_from_slice(&bytes[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Inflate a zlib (with header) or raw deflate stream using the streaming API,
/// which reports exactly how much input the stream used.
fn inflate(input: &[u8], zlib_header: bool, max_out: usize) -> Result<(Vec<u8>, usize, bool, bool), String> {
    let mut decoder = flate2::Decompress::new(zlib_header);
    let mut out: Vec<u8> = Vec::with_capacity(input.len().min(max_out).max(1024) * 2);
    loop {
        let in_pos = decoder.total_in() as usize;
        let before_out = out.len();
        if out.capacity() == out.len() {
            out.reserve(64 * 1024);
        }
        let status = decoder
            .decompress_vec(&input[in_pos..], &mut out, flate2::FlushDecompress::None)
            .map_err(|e| e.to_string())?;
        if status == flate2::Status::StreamEnd {
            return Ok((out, decoder.total_in() as usize, true, false));
        }
        if out.len() >= max_out {
            out.truncate(max_out);
            return Ok((out, decoder.total_in() as usize, false, true));
        }
        let in_now = decoder.total_in() as usize;
        if in_now >= input.len() && out.len() == before_out {
            return Err("stream ends before its data does".to_string());
        }
        if in_now == in_pos && out.len() == before_out {
            return Err("decoder made no progress".to_string());
        }
    }
}

/// Length of a gzip member header (RFC 1952), including optional fields.
fn gzip_header_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 10 || bytes[0] != 0x1F || bytes[1] != 0x8B || bytes[2] != 8 {
        return None;
    }
    let flags = bytes[3];
    let mut pos = 10;
    if flags & 0x04 != 0 {
        let extra_len = u16::from_le_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
        pos += 2 + extra_len;
    }
    if flags & 0x08 != 0 {
        pos += bytes.get(pos..)?.iter().position(|&b| b == 0)? + 1;
    }
    if flags & 0x10 != 0 {
        pos += bytes.get(pos..)?.iter().position(|&b| b == 0)? + 1;
    }
    if flags & 0x02 != 0 {
        pos += 2;
    }
    (pos <= bytes.len()).then_some(pos)
}

/// Try every codec at the start of `input` and return the ones that decode.
/// Header-bearing codecs are tried first, then headerless ones; a headerless
/// decode must produce a reasonable amount of output to count.
pub fn probe(input: &[u8], max_out: usize) -> Vec<Decompressed> {
    const MIN_HEADERLESS_OUTPUT: usize = 64;
    let mut found = Vec::new();
    if let Some(codec) = detect_header(input)
        && let Ok(result) = decompress(codec, input, max_out)
        && (result.complete || result.truncated)
    {
        found.push(result);
    }
    for codec in Codec::HEADERLESS {
        if let Ok(result) = decompress(codec, input, max_out)
            && (result.complete || result.truncated)
            && result.data.len() >= MIN_HEADERLESS_OUTPUT
            && result.consumed >= 8
        {
            found.push(result);
        }
    }
    found
}

/// Compress `data` with `codec` (must be in [`Codec::COMPRESSIBLE`]).
pub fn compress(codec: Codec, data: &[u8]) -> Result<Vec<u8>, String> {
    let level = flate2::Compression::best();
    match codec {
        Codec::Zlib => {
            let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), level);
            encoder.write_all(data).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())
        }
        Codec::Gzip => {
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), level);
            encoder.write_all(data).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())
        }
        Codec::Deflate => {
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), level);
            encoder.write_all(data).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())
        }
        Codec::Bzip2 => {
            let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
            encoder.write_all(data).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())
        }
        Codec::Lz4 => {
            let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
            encoder.write_all(data).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())
        }
        Codec::Xz | Codec::Lzma | Codec::Zstd => Err(format!("{} compression is not supported", codec.label())),
    }
}

/// A built-in codec exposed through the plugin API.
struct BuiltinCodec(Codec);

impl CodecPlugin for BuiltinCodec {
    fn id(&self) -> &str {
        match self.0 {
            Codec::Zlib => "zlib",
            Codec::Gzip => "gzip",
            Codec::Deflate => "deflate",
            Codec::Bzip2 => "bzip2",
            Codec::Xz => "xz",
            Codec::Lzma => "lzma",
            Codec::Zstd => "zstd",
            Codec::Lz4 => "lz4",
        }
    }

    fn name(&self) -> &str {
        self.0.label()
    }

    fn kind(&self) -> CodecKind {
        CodecKind::Compression
    }

    fn detect(&self, bytes: &[u8]) -> bool {
        detect_header(bytes) == Some(self.0)
    }

    fn decode(&self, input: &[u8], max_out: usize) -> Result<Decoded, String> {
        decompress(self.0, input, max_out).map(|d| Decoded {
            data: d.data,
            consumed: d.consumed,
            consumed_exact: d.consumed_exact,
            complete: d.complete,
            truncated: d.truncated,
        })
    }

    fn encode(&self, data: &[u8]) -> Option<Result<Vec<u8>, String>> {
        Codec::COMPRESSIBLE.contains(&self.0).then(|| compress(self.0, data))
    }
}

/// Every built-in codec, ready to register.
pub fn builtin_codecs() -> Vec<Arc<dyn CodecPlugin>> {
    [Codec::Gzip, Codec::Zlib, Codec::Deflate, Codec::Bzip2, Codec::Xz, Codec::Lzma, Codec::Zstd, Codec::Lz4]
        .into_iter()
        .map(|codec| Arc::new(BuiltinCodec(codec)) as Arc<dyn CodecPlugin>)
        .collect()
}

/// Output cap while verifying a candidate header.
const VERIFY_MAX_OUT: usize = 64 * 1024;
/// Output cap when measuring an accepted stream.
pub const MEASURE_MAX_OUT: usize = 64 * 1024 * 1024;
/// Verified streams must decode to at least this much, unless they end cleanly.
const MIN_VERIFIED_OUTPUT: usize = 16;

/// Find verified compressed streams in `window`, whose first byte is at
/// document offset `base`.
pub fn scan_streams(window: &[u8], base: usize) -> Vec<Stream> {
    let mut streams = Vec::new();
    let mut pos = 0;
    while pos + 2 <= window.len() {
        let Some(codec) = detect_header(&window[pos..]) else {
            pos += 1;
            continue;
        };
        let Ok(verified) = decompress(codec, &window[pos..], VERIFY_MAX_OUT) else {
            pos += 1;
            continue;
        };
        let plausible = verified.complete || verified.truncated;
        if !plausible || (verified.data.len() < MIN_VERIFIED_OUTPUT && !verified.complete) {
            pos += 1;
            continue;
        }
        let measured = if verified.truncated {
            decompress(codec, &window[pos..], MEASURE_MAX_OUT).unwrap_or(verified)
        } else {
            verified
        };
        let compressed_len = measured.consumed.max(1);
        streams.push(Stream {
            codec,
            start: base + pos,
            compressed_len,
            decompressed_len: measured.data.len(),
            complete: measured.complete,
            truncated: measured.truncated,
        });
        pos += compressed_len;
    }
    streams
}

/// Human readable byte count for descriptions.
pub fn human_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

impl Stream {
    pub fn describe(&self) -> String {
        let ratio = self.decompressed_len as f64 / self.compressed_len.max(1) as f64;
        let more = if self.truncated { " or more" } else { "" };
        let state = if self.complete { "" } else if self.truncated { ", not fully measured" } else { ", incomplete" };
        format!(
            "{} stream: {} compressed, {}{} decompressed ({ratio:.1}×){state}",
            self.codec.label(),
            human_bytes(self.compressed_len),
            human_bytes(self.decompressed_len),
            more
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_text() -> Vec<u8> {
        let mut text = Vec::new();
        for i in 0..400 {
            text.extend_from_slice(format!("record {i:04} the quick brown fox jumps over the lazy dog\n").as_bytes());
        }
        text
    }

    /// A minimal zstd frame with one raw block holding "hello" (ruzstd decodes only).
    const ZSTD_HELLO: &[u8] = &[0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x05, 0x29, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o'];

    #[test]
    fn round_trips_every_compressible_codec() {
        let text = sample_text();
        for codec in Codec::COMPRESSIBLE {
            let packed = compress(codec, &text).unwrap();
            assert!(packed.len() < text.len(), "{codec:?} did not shrink");
            let unpacked = decompress(codec, &packed, usize::MAX).unwrap();
            assert_eq!(unpacked.data, text, "{codec:?}");
            assert!(unpacked.complete);
            if unpacked.consumed_exact {
                assert_eq!(unpacked.consumed, packed.len(), "{codec:?} consumed");
            }
        }
    }

    #[test]
    fn detects_headers_and_rejects_noise() {
        let text = sample_text();
        for codec in [Codec::Zlib, Codec::Gzip, Codec::Bzip2, Codec::Lz4] {
            let packed = compress(codec, &text).unwrap();
            assert_eq!(detect_header(&packed), Some(codec));
        }
        assert_eq!(detect_header(ZSTD_HELLO), Some(Codec::Zstd));
        assert_eq!(detect_header(b"\xFD7zXZ\x00"), Some(Codec::Xz));
        assert_eq!(detect_header(b"hello world"), None);
        assert_eq!(detect_header(&[0x78, 0x9C]), Some(Codec::Zlib));
        assert_eq!(detect_header(&[0x78, 0x9D]), None, "bad check bits");
    }

    #[test]
    fn xz_and_zstd_decode() {
        let text = sample_text();
        let mut packed = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(&text), &mut packed).unwrap();
        let unpacked = decompress(Codec::Xz, &packed, usize::MAX).unwrap();
        assert_eq!(unpacked.data, text);
        assert_eq!(unpacked.consumed, packed.len());

        let hello = decompress(Codec::Zstd, ZSTD_HELLO, usize::MAX).unwrap();
        assert_eq!(hello.data, b"hello");
    }

    #[test]
    fn output_limit_marks_truncation_instead_of_inflating_everything() {
        let text = sample_text();
        let packed = compress(Codec::Zlib, &text).unwrap();
        let partial = decompress(Codec::Zlib, &packed, 1000).unwrap();
        assert_eq!(partial.data.len(), 1000);
        assert!(partial.truncated && !partial.complete);
        let partial = decompress(Codec::Bzip2, &compress(Codec::Bzip2, &text).unwrap(), 1000).unwrap();
        assert!(partial.truncated);
    }

    #[test]
    fn scan_finds_embedded_streams_and_reports_their_extent() {
        let text = sample_text();
        let mut state = 0x1234_5678u32;
        let mut noise = |n: usize| -> Vec<u8> {
            (0..n)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    (state >> 24) as u8
                })
                .collect()
        };
        let zlib = compress(Codec::Zlib, &text).unwrap();
        let gzip = compress(Codec::Gzip, &text).unwrap();
        let bz = compress(Codec::Bzip2, &text).unwrap();
        let lz4 = compress(Codec::Lz4, &text).unwrap();
        let mut file = noise(3000);
        let zlib_at = file.len();
        file.extend_from_slice(&zlib);
        file.extend_from_slice(&noise(500));
        let gzip_at = file.len();
        file.extend_from_slice(&gzip);
        let bz_at = file.len();
        file.extend_from_slice(&bz);
        file.extend_from_slice(&noise(100));
        let lz4_at = file.len();
        file.extend_from_slice(&lz4);
        let zstd_at = file.len();
        file.extend_from_slice(ZSTD_HELLO);
        file.extend_from_slice(&noise(2000));

        let streams = scan_streams(&file, 1000);
        let find = |codec: Codec| streams.iter().find(|s| s.codec == codec).unwrap_or_else(|| panic!("{codec:?} in {streams:?}"));
        let z = find(Codec::Zlib);
        assert_eq!((z.start, z.compressed_len, z.decompressed_len, z.complete), (1000 + zlib_at, zlib.len(), text.len(), true));
        let g = find(Codec::Gzip);
        assert_eq!((g.start, g.compressed_len), (1000 + gzip_at, gzip.len()));
        assert_eq!(find(Codec::Bzip2).start, 1000 + bz_at);
        assert_eq!(find(Codec::Lz4).start, 1000 + lz4_at);
        let zs = find(Codec::Zstd);
        assert_eq!((zs.start, zs.decompressed_len), (1000 + zstd_at, 5));
        assert_eq!(streams.len(), 5, "no false positives in noise: {streams:?}");
    }

    #[test]
    fn codec_plugins_wrap_the_builtin_codecs() {
        let codecs = builtin_codecs();
        let text = sample_text();
        let gzip = codecs.iter().find(|c| c.id() == "gzip").unwrap();
        let packed = gzip.encode(&text).expect("gzip encodes").unwrap();
        assert!(gzip.detect(&packed));
        assert!(!gzip.detect(b"nope"));
        let decoded = gzip.decode(&packed, usize::MAX).unwrap();
        assert_eq!(decoded.data, text);
        assert!(codecs.iter().find(|c| c.id() == "xz").unwrap().encode(&text).is_none());
    }

    #[test]
    fn probe_finds_raw_deflate_without_a_header() {
        let text = sample_text();
        let raw = compress(Codec::Deflate, &text).unwrap();
        let found = probe(&raw, usize::MAX);
        assert!(found.iter().any(|d| d.codec == Codec::Deflate && d.data == text), "{:?}", found.iter().map(|d| d.codec).collect::<Vec<_>>());
        assert!(probe(b"definitely not compressed data at all, just text", usize::MAX).is_empty());
    }

    #[test]
    fn gzip_header_with_name_and_extra_is_measured_exactly() {
        let text = sample_text();
        let mut packed = compress(Codec::Gzip, &text).unwrap();
        // Insert an FNAME field by hand.
        packed[3] |= 0x08;
        let mut with_name = packed[..10].to_vec();
        with_name.extend_from_slice(b"file.txt\0");
        with_name.extend_from_slice(&packed[10..]);
        let unpacked = decompress(Codec::Gzip, &with_name, usize::MAX).unwrap();
        assert_eq!(unpacked.data, text);
        assert_eq!(unpacked.consumed, with_name.len());
    }
}
