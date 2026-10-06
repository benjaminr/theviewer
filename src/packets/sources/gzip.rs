//! Captures compressed whole with gzip, as `tcpdump -w - | gzip` and
//! Wireshark's "Compress with gzip" option write them.
//!
//! The packets of such a capture are not ranges of the compressed bytes, so
//! the capture is decompressed (to at most [`MAX_GUNZIPPED_LEN`] bytes) and
//! read from the decompressed copy: the packet viewer opens that copy as a
//! document of its own.

use super::{CaptureFormat, SourceError, format_by_magic};
use crate::compress::{self, Codec};

/// Most bytes a compressed capture is decompressed to.
pub const MAX_GUNZIPPED_LEN: usize = 128 * 1024 * 1024;
/// The gzip header's magic and its only compression method, deflate.
const GZIP_MAGIC: [u8; 3] = [0x1F, 0x8B, 0x08];
/// Decompressed bytes enough to recognise any capture header by its magic.
const PROBE_LEN: usize = 16;

/// A capture decompressed from gzip.
#[derive(Clone, Debug, PartialEq)]
pub struct GunzippedCapture {
    pub format: CaptureFormat,
    pub data: Vec<u8>,
    /// Bytes of the gzip stream, header and trailer included.
    pub compressed_len: usize,
    /// The capture was cut at [`MAX_GUNZIPPED_LEN`].
    pub truncated: bool,
}

/// Whether `bytes` start with a gzip header.
pub fn looks_like(bytes: &[u8]) -> bool {
    bytes.starts_with(&GZIP_MAGIC)
}

/// The capture format inside the gzip stream at `bytes[0]`, found by
/// decompressing its first few bytes.
pub fn inner_format(bytes: &[u8]) -> Option<CaptureFormat> {
    if !looks_like(bytes) {
        return None;
    }
    let start = compress::decompress(Codec::Gzip, bytes, PROBE_LEN).ok()?;
    format_by_magic(&start.data)
}

/// The capture inside the gzip stream at `bytes[0]` (document offset
/// `base`), decompressed.
pub fn gunzip(bytes: &[u8], base: usize) -> Result<GunzippedCapture, SourceError> {
    let format = inner_format(bytes).ok_or(SourceError::NotACapture { offset: base })?;
    let decompressed = compress::decompress(Codec::Gzip, bytes, MAX_GUNZIPPED_LEN)
        .map_err(|reason| SourceError::UnreadableCapture { offset: base, format: "gzip-compressed", reason: format!("the gzip stream does not decompress ({reason})") })?;
    Ok(GunzippedCapture { format, compressed_len: decompressed.consumed.min(bytes.len()), truncated: decompressed.truncated, data: decompressed.data })
}

#[cfg(test)]
mod tests {
    use super::super::snoop;
    use super::*;

    fn gzipped(data: &[u8]) -> Vec<u8> {
        compress::compress(Codec::Gzip, data).expect("compresses")
    }

    #[test]
    fn a_gzipped_capture_is_recognised_and_decompressed() {
        let capture = snoop::tests::snoop_file(4, &[(b"frame", 1, 0)]);
        let file = gzipped(&capture);
        assert_eq!(inner_format(&file), Some(CaptureFormat::Snoop));
        let gunzipped = gunzip(&file, 0).expect("a capture");
        assert_eq!(gunzipped.data, capture);
        assert_eq!(gunzipped.compressed_len, file.len());
        assert!(!gunzipped.truncated);
    }

    #[test]
    fn gzip_of_anything_else_is_not_a_capture() {
        let file = gzipped(b"just some text, compressed");
        assert_eq!(inner_format(&file), None);
        assert_eq!(gunzip(&file, 7), Err(SourceError::NotACapture { offset: 7 }));
        assert_eq!(inner_format(b"\x1F\x8B\x08 but nothing that inflates"), None);
    }

    #[test]
    fn a_cut_gzip_stream_gives_what_decompressed_without_panicking() {
        let capture = snoop::tests::snoop_file(4, &[(&[0x5A; 4000], 1, 0), (&[0xA5; 4000], 2, 0)]);
        let file = gzipped(&capture);
        for cut in 0..file.len() {
            if let Ok(gunzipped) = gunzip(&file[..cut], 0) {
                assert!(capture.starts_with(&gunzipped.data));
            }
        }
    }
}
