//! HTTP/1 messages read from a followed TCP stream: each request and
//! response with its head, and its body as the sender meant it, put
//! together across segments, de-chunked when it was sent chunked, and
//! decompressed when its `Content-Encoding` is gzip or deflate.
//!
//! Each direction of the stream is read on its own, so a request and the
//! response to it come out as two messages. Nothing here can panic, and the
//! bodies are capped.

use std::io::Read;

use super::is_http_start_line;
use crate::packets::flows::Stream;

/// Most bytes a body is decompressed to.
pub const MAX_BODY: usize = 64 * 1024 * 1024;
/// Longest head (start line and headers) looked for.
const MAX_HEAD: usize = 64 * 1024;
/// Most messages read from one direction of a stream.
const MAX_MESSAGES: usize = 1_000;

/// One HTTP request or response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpMessage {
    /// Sent from the conversation's first endpoint to its second.
    pub a_to_b: bool,
    /// Index of the packet the message starts in.
    pub packet: usize,
    /// The request or status line.
    pub start_line: String,
    pub headers: Vec<(String, String)>,
    /// The body as sent, chunk framing and all.
    pub body_on_wire: usize,
    /// Whether it was sent with `Transfer-Encoding: chunked`.
    pub chunked: bool,
    /// Its `Content-Encoding`, if any.
    pub content_encoding: Option<String>,
    /// The body, de-chunked, and decompressed when `decoded`.
    pub body: Vec<u8>,
    /// Whether the content encoding was undone.
    pub decoded: bool,
    /// What could not be done, such as a body cut short.
    pub notes: Vec<String>,
}

impl HttpMessage {
    /// A header's value, by its name in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    pub fn is_request(&self) -> bool {
        !self.start_line.starts_with("HTTP/")
    }

    /// A response that never has a body: 1xx, 204 No Content or 304 Not Modified.
    fn has_no_body(&self) -> bool {
        let code = self.start_line.split(' ').nth(1).unwrap_or_default();
        !self.is_request() && (code.starts_with('1') || code == "204" || code == "304")
    }
}

/// Every HTTP message in `stream`, in the order each starts, the two
/// directions read apart.
pub fn http_messages(stream: &Stream) -> Vec<HttpMessage> {
    let mut messages = Vec::new();
    for a_to_b in [true, false] {
        let mut bytes = Vec::new();
        // (offset in `bytes`, packet) where each segment starts.
        let mut starts: Vec<(usize, usize)> = Vec::new();
        for segment in stream.segments.iter().filter(|segment| segment.a_to_b == a_to_b) {
            starts.push((bytes.len(), segment.packet));
            bytes.extend_from_slice(&stream.bytes[segment.start..segment.start + segment.len]);
        }
        let packet_at = |offset: usize| starts.iter().rev().find(|(start, _)| *start <= offset).map_or(0, |&(_, packet)| packet);
        let mut at = 0;
        while at < bytes.len() && messages.len() < MAX_MESSAGES {
            let Some((mut message, next)) = read_message(&bytes, at) else { break };
            message.a_to_b = a_to_b;
            message.packet = packet_at(at);
            messages.push(message);
            if next <= at {
                break;
            }
            at = next;
        }
    }
    messages.sort_by_key(|message| message.packet);
    messages
}

/// The message whose head starts at `at`, and where the next one starts.
fn read_message(bytes: &[u8], at: usize) -> Option<(HttpMessage, usize)> {
    let rest = &bytes[at..];
    let head_end = rest.windows(4).take(MAX_HEAD).position(|window| window == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&rest[..head_end]);
    let mut lines = head.split("\r\n");
    let start_line = lines.next()?.to_string();
    if !is_http_start_line(&start_line) {
        return None;
    }
    let headers: Vec<(String, String)> = lines.filter_map(|line| line.split_once(':')).map(|(name, value)| (name.trim().to_string(), value.trim().to_string())).collect();
    let mut message = HttpMessage { start_line, headers, ..HttpMessage::default() };
    let body_start = at + head_end + 4;
    let available = &bytes[body_start..];
    message.chunked = message.header("Transfer-Encoding").is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    message.content_encoding = message.header("Content-Encoding").map(|value| value.trim().to_ascii_lowercase()).filter(|value| !value.is_empty() && value != "identity");
    let content_length = message.header("Content-Length").and_then(|value| value.trim().parse::<usize>().ok());
    let (raw, used) = if message.chunked {
        let (body, used, complete) = dechunk(available);
        if !complete {
            message.notes.push("the chunked body is cut short: the stream ends before its last chunk".to_string());
        }
        (body, used)
    } else if let Some(length) = content_length {
        if length > available.len() {
            message.notes.push(format!("the body is cut short: Content-Length says {length} bytes, the stream holds {}", available.len()));
        }
        let used = length.min(available.len());
        (available[..used].to_vec(), used)
    } else if message.is_request() || message.has_no_body() {
        (Vec::new(), 0)
    } else {
        // A response without a length runs to the end of the connection.
        (available.to_vec(), available.len())
    };
    message.body_on_wire = used;
    message.body = raw;
    if let Some(encoding) = message.content_encoding.clone() {
        match decode_content(&message.body, &encoding) {
            Ok(decoded) => {
                message.body = decoded;
                message.decoded = true;
            }
            Err(reason) => message.notes.push(reason),
        }
    }
    Some((message, body_start + used))
}

/// A chunked body put back together: the data, the bytes the chunks took
/// on the wire, and whether the last (empty) chunk was reached.
pub fn dechunk(bytes: &[u8]) -> (Vec<u8>, usize, bool) {
    let mut body = Vec::new();
    let mut at = 0;
    loop {
        let Some(line_end) = find_crlf(bytes, at) else { return (body, bytes.len(), false) };
        let line = String::from_utf8_lossy(&bytes[at..line_end]);
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else { return (body, at, false) };
        at = line_end + 2;
        if size == 0 {
            // Trailers, then an empty line.
            loop {
                let Some(end) = find_crlf(bytes, at) else { return (body, bytes.len(), true) };
                let empty = end == at;
                at = end + 2;
                if empty {
                    return (body, at, true);
                }
            }
        }
        let end = at.saturating_add(size).min(bytes.len());
        if body.len() + (end - at) > MAX_BODY {
            return (body, at, false);
        }
        body.extend_from_slice(&bytes[at..end]);
        if end < at + size {
            return (body, bytes.len(), false);
        }
        at = end;
        if bytes.get(at..at + 2) == Some(b"\r\n") {
            at += 2;
        }
    }
}

fn find_crlf(bytes: &[u8], from: usize) -> Option<usize> {
    bytes.get(from..)?.windows(2).position(|window| window == b"\r\n").map(|at| from + at)
}

/// `body` with its content encoding undone: gzip, or deflate (zlib-wrapped
/// or raw, as servers send both).
pub fn decode_content(body: &[u8], encoding: &str) -> Result<Vec<u8>, String> {
    let limited = |reader: &mut dyn Read| -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        reader.take(MAX_BODY as u64).read_to_end(&mut out)?;
        Ok(out)
    };
    let result = match encoding {
        "gzip" | "x-gzip" => limited(&mut flate2::read::MultiGzDecoder::new(body)),
        "deflate" => limited(&mut flate2::read::ZlibDecoder::new(body)).or_else(|_| limited(&mut flate2::read::DeflateDecoder::new(body))),
        other => return Err(format!("the body's Content-Encoding is {other}, which is not undone here")),
    };
    result.map_err(|error| format!("the {encoding} body does not decompress: {error}"))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::packets::flows::{ConversationKey, Endpoint, StreamSegment, Transport};

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// A stream of `parts`, each `(a_to_b, packet, bytes)`.
    fn stream(parts: &[(bool, usize, &[u8])]) -> Stream {
        let endpoint = |port| Endpoint { address: "10.0.0.1".parse().unwrap(), port: Some(port) };
        let mut stream = Stream { key: ConversationKey { transport: Transport::Tcp, a: endpoint(1), b: endpoint(80) }, bytes: Vec::new(), segments: Vec::new(), retransmissions: 0, truncated: false };
        for &(a_to_b, packet, bytes) in parts {
            stream.segments.push(StreamSegment { packet, a_to_b, start: stream.bytes.len(), len: bytes.len() });
            stream.bytes.extend_from_slice(bytes);
        }
        stream
    }

    #[test]
    fn a_chunked_gzipped_upload_split_over_segments_comes_out_as_the_file_sent() {
        let file = b"PK\x03\x04 the second half of an archive".repeat(20);
        let compressed = gzip(&file);
        let (first, second) = compressed.split_at(compressed.len() / 2);
        let mut body = format!("{:x};name=one\r\n", first.len()).into_bytes();
        body.extend_from_slice(first);
        body.extend_from_slice(format!("\r\n{:X}\r\n", second.len()).as_bytes());
        body.extend_from_slice(second);
        body.extend_from_slice(b"\r\n0\r\nX-Trailer: yes\r\n\r\n");
        let mut request = b"POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        request.extend_from_slice(&body);
        let (head, tail) = request.split_at(70);
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let messages = http_messages(&stream(&[(true, 3, head), (false, 4, b"HTTP/1.1 100 Continue\r\n\r\n"), (true, 5, tail), (false, 6, response)]));
        assert_eq!(messages.len(), 3);
        let upload = &messages[0];
        assert_eq!((upload.packet, upload.start_line.as_str(), upload.chunked, upload.decoded), (3, "POST /upload HTTP/1.1", true, true));
        assert_eq!(upload.body, file, "{:?}", upload.notes);
        assert_eq!(upload.body_on_wire, body.len());
        assert_eq!(messages[2].body, b"ok");
        assert!(messages[1].body.is_empty(), "100 Continue has no body");
    }

    #[test]
    fn a_body_cut_short_or_in_an_encoding_not_undone_is_said() {
        let messages = http_messages(&stream(&[(false, 0, b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Encoding: br\r\n\r\nabc")]));
        assert_eq!(messages[0].body, b"abc");
        assert!(!messages[0].decoded);
        assert!(messages[0].notes.iter().any(|note| note.contains("cut short")), "{:?}", messages[0].notes);
        assert!(messages[0].notes.iter().any(|note| note.contains("br")), "{:?}", messages[0].notes);
        assert!(http_messages(&stream(&[(true, 0, b"\x16\x03\x01 not http")])).is_empty());
        let (body, _, complete) = dechunk(b"5\r\nhel");
        assert_eq!((body.as_slice(), complete), (&b"hel"[..], false));
    }

    #[test]
    fn deflate_is_undone_with_or_without_its_zlib_wrapper() {
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(b"hello hello").unwrap();
        assert_eq!(decode_content(&zlib.finish().unwrap(), "deflate").unwrap(), b"hello hello");
        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(b"hello hello").unwrap();
        assert_eq!(decode_content(&raw.finish().unwrap(), "deflate").unwrap(), b"hello hello");
        assert!(decode_content(b"not gzip", "gzip").is_err());
    }
}
