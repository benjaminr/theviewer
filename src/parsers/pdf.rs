//! PDF documents walked by hand: the header, each indirect object with its
//! dictionary and stream (its /Filter and where its data lies), the files
//! embedded through /EmbeddedFile streams and the file specifications that
//! name them, and the cross-reference table and trailer.
//!
//! The walk is lexical, not a full PDF reader: objects are found by their
//! "N G obj" headers, a stream's data runs for its /Length when that is a
//! direct number and up to "endstream" otherwise, and nothing is decoded.

use super::{MAX_CHILDREN, MAX_EXTENT, human_bytes, text_preview};
use crate::plugin::{Category, Field, Finding, Parser};

const SOURCE: &str = "parsers.pdf";
const HEADER: &[u8] = b"%PDF-";
const END_OF_FILE: &[u8] = b"%%EOF";
/// Most of an object's dictionary shown as its value.
const DICTIONARY_PREVIEW: usize = 120;

pub struct PdfParser;

/// One indirect object, its offsets relative to the parsed bytes.
struct Object {
    number: u32,
    generation: u32,
    start: usize,
    end: usize,
    /// The object's text before any stream: usually a dictionary.
    dictionary: (usize, usize),
    stream: Option<Stream>,
}

struct Stream {
    start: usize,
    len: usize,
    /// "/FlateDecode", "[/ASCII85Decode /FlateDecode]", or none.
    filter: Option<String>,
}

impl Object {
    fn dictionary<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.dictionary.0..self.dictionary.1]
    }
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'\x0C' | b'\0')
}

fn is_delimiter(byte: u8) -> bool {
    is_whitespace(byte) || matches!(byte, b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'%')
}

fn find(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes.get(from..)?.windows(needle.len()).position(|window| window == needle).map(|at| from + at)
}

/// The digits ending just before `end` (after any whitespace), as a number
/// and where they start.
fn number_before(bytes: &[u8], end: usize) -> Option<(u32, usize)> {
    let mut at = end;
    while at > 0 && is_whitespace(bytes[at - 1]) {
        at -= 1;
    }
    let digits_end = at;
    while at > 0 && bytes[at - 1].is_ascii_digit() {
        at -= 1;
    }
    if at == digits_end || digits_end - at > 10 {
        return None;
    }
    let number = std::str::from_utf8(&bytes[at..digits_end]).ok()?.parse().ok()?;
    Some((number, at))
}

/// The "N G obj" header whose "obj" keyword is at `keyword`: the object and
/// generation numbers, and where the header starts.
fn object_header(bytes: &[u8], keyword: usize) -> Option<(u32, u32, usize)> {
    if bytes.get(keyword + 3).is_some_and(|&after| !is_delimiter(after)) || keyword == 0 || !is_whitespace(bytes[keyword - 1]) {
        return None;
    }
    let (generation, generation_at) = number_before(bytes, keyword)?;
    if generation_at == 0 || !is_whitespace(bytes[generation_at - 1]) {
        return None;
    }
    let (number, start) = number_before(bytes, generation_at)?;
    (start == 0 || is_whitespace(bytes[start - 1])).then_some((number, generation, start))
}

/// The token after `/key` in a dictionary: a name, number, reference,
/// string or array, as written.
fn value_of(dictionary: &[u8], key: &[u8]) -> Option<String> {
    let mut search = 0;
    let at = loop {
        let at = find(dictionary, search, key)?;
        let after = at + key.len();
        if dictionary.get(after).is_none_or(|&byte| is_delimiter(byte)) {
            break after;
        }
        search = after;
    };
    let rest = &dictionary[at..];
    let start = rest.iter().position(|&byte| !is_whitespace(byte))?;
    let rest = &rest[start..];
    let len = match rest.first()? {
        b'[' => rest.iter().position(|&byte| byte == b']')? + 1,
        b'(' => literal_string_len(rest)?,
        b'/' => 1 + rest[1..].iter().position(|&byte| is_delimiter(byte)).unwrap_or(rest.len() - 1),
        _ => {
            // A number, or a reference "N G R".
            let words: Vec<&[u8]> = rest.split(|&byte| is_whitespace(byte)).filter(|word| !word.is_empty()).take(3).collect();
            let is_reference = words.len() == 3 && words[2].starts_with(b"R") && words[..2].iter().all(|word| word.iter().all(u8::is_ascii_digit));
            let first_len = rest.iter().position(|&byte| is_delimiter(byte)).unwrap_or(rest.len());
            if is_reference { find(rest, 0, b"R")? + 1 } else { first_len }
        }
    };
    Some(String::from_utf8_lossy(&rest[..len]).into_owned())
}

/// Length of the literal string at the start of `text`, parentheses
/// included, minding nesting and backslash escapes.
fn literal_string_len(text: &[u8]) -> Option<usize> {
    let mut depth = 0usize;
    let mut escaped = false;
    for (index, &byte) in text.iter().enumerate() {
        match byte {
            _ if escaped => escaped = false,
            b'\\' => escaped = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// "(bom_rev3.csv)" as "bom_rev3.csv".
fn unquoted(text: &str) -> String {
    text.strip_prefix('(').and_then(|inner| inner.strip_suffix(')')).unwrap_or(text).to_string()
}

/// The object number a reference "7 0 R" points at.
fn referenced(text: &str) -> Option<u32> {
    let mut words = text.split_whitespace();
    let number = words.next()?.parse().ok()?;
    (words.nth(1) == Some("R")).then_some(number)
}

/// The stream that follows a dictionary ending at `keyword` (where
/// "stream" is), its data running for /Length or up to "endstream".
fn read_stream(bytes: &[u8], dictionary: &[u8], keyword: usize) -> Stream {
    let mut start = keyword + b"stream".len();
    if bytes.get(start) == Some(&b'\r') {
        start += 1;
    }
    if bytes.get(start) == Some(&b'\n') {
        start += 1;
    }
    let declared = value_of(dictionary, b"/Length").and_then(|length| length.parse::<usize>().ok());
    let ends_there = |len: usize| {
        let Some(after) = start.checked_add(len) else { return false };
        bytes.get(after..).is_some_and(|rest| {
            let skip = rest.iter().take(2).take_while(|&&byte| byte == b'\r' || byte == b'\n').count();
            rest[skip..].starts_with(b"endstream")
        })
    };
    let len = match declared {
        Some(len) if ends_there(len) => len,
        _ => {
            let end = find(bytes, start, b"endstream").unwrap_or(bytes.len());
            let mut len = end - start;
            // The end-of-line before "endstream" is not part of the data.
            while len > 0 && matches!(bytes[start + len - 1], b'\r' | b'\n') {
                len -= 1;
            }
            len
        }
    };
    Stream { start, len, filter: value_of(dictionary, b"/Filter") }
}

/// Every indirect object in `bytes`, in order, stream data skipped over.
fn objects(bytes: &[u8]) -> Vec<Object> {
    let mut found = Vec::new();
    let mut search = 0;
    while found.len() < MAX_CHILDREN && search < bytes.len().min(MAX_EXTENT) {
        let Some(keyword) = find(bytes, search, b"obj") else { break };
        search = keyword + 3;
        let Some((number, generation, start)) = object_header(bytes, keyword) else { continue };
        let body = keyword + 3;
        // A stream's keyword comes before its data, so before any "endobj"
        // the data may happen to hold; looking no further than the first
        // "endobj" keeps the walk linear.
        let end_at = find(bytes, body, b"endobj");
        let stream_at = find(&bytes[..end_at.unwrap_or(bytes.len())], body, b"stream");
        let (dictionary_end, stream) = match (stream_at, end_at) {
            (Some(stream_at), _) => (stream_at, Some(read_stream(bytes, &bytes[body..stream_at], stream_at))),
            (None, Some(end)) => (end, None),
            (None, None) => break,
        };
        let after = stream.as_ref().map_or(dictionary_end, |stream| stream.start + stream.len);
        let end = find(bytes, after, b"endobj").map_or(bytes.len(), |at| at + b"endobj".len());
        found.push(Object { number, generation, start, end, dictionary: (body, dictionary_end), stream });
        search = end;
    }
    found
}

/// The embedded files: each file specification's name with the stream it
/// points at, and any /EmbeddedFile stream no specification names.
fn embedded_files(bytes: &[u8], objects: &[Object]) -> Vec<(String, usize)> {
    let mut files = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        let dictionary = object.dictionary(bytes);
        let Some(ef) = find(dictionary, 0, b"/EF") else { continue };
        let name = value_of(dictionary, b"/UF").or_else(|| value_of(dictionary, b"/F")).map(|name| unquoted(&name)).unwrap_or_else(|| format!("object {}", object.number));
        let target = value_of(&dictionary[ef..], b"/F").and_then(|reference| referenced(&reference));
        if let Some(stream) = target.and_then(|number| objects.iter().position(|other| other.number == number && other.stream.is_some())) {
            files.push((name, stream));
        } else {
            files.push((name, index));
        }
    }
    for (index, object) in objects.iter().enumerate() {
        let is_embedded = value_of(object.dictionary(bytes), b"/Type").as_deref() == Some("/EmbeddedFile");
        if is_embedded && object.stream.is_some() && !files.iter().any(|&(_, stream)| stream == index) {
            files.push((format!("object {}", object.number), index));
        }
    }
    files
}

fn object_field(bytes: &[u8], object: &Object, base: usize) -> Field {
    let dictionary = object.dictionary(bytes);
    let kind = value_of(dictionary, b"/Type");
    let mut summary = kind.clone().unwrap_or_else(|| "object".to_string());
    let mut children = vec![Field::new("dictionary", base + object.dictionary.0, object.dictionary.1 - object.dictionary.0, text_preview(dictionary.trim_ascii(), DICTIONARY_PREVIEW))];
    if let Some(stream) = &object.stream {
        let filter = stream.filter.as_deref().unwrap_or("no filter");
        summary.push_str(&format!(", stream of {} ({filter})", human_bytes(stream.len as u64)));
        children.push(Field::new("stream data", base + stream.start, stream.len, format!("{} bytes, {filter}", stream.len)));
    }
    Field::new(format!("object {} {}", object.number, object.generation), base + object.start, object.end - object.start, summary).with_children(children)
}

impl Parser for PdfParser {
    fn id(&self) -> &str {
        "pdf"
    }

    fn name(&self) -> &str {
        "PDF document"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(HEADER)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let bytes = &bytes[..bytes.len().min(MAX_EXTENT)];
        let header_end = bytes.iter().position(|&byte| byte == b'\r' || byte == b'\n').unwrap_or(bytes.len());
        let version = String::from_utf8_lossy(&bytes[HEADER.len()..header_end]).trim().to_string();
        let objects = objects(bytes);
        if objects.is_empty() {
            return None;
        }
        let last_end_of_file = bytes.windows(END_OF_FILE.len()).rposition(|window| window == END_OF_FILE);
        let extent = match last_end_of_file {
            Some(at) => {
                let after = at + END_OF_FILE.len();
                after + bytes[after..].iter().take(2).take_while(|&&byte| byte == b'\r' || byte == b'\n').count()
            }
            None => objects.last().map_or(header_end, |object| object.end),
        };
        let mut fields = vec![Field::new("header", base, header_end, format!("PDF {version}"))];
        let object_fields: Vec<Field> = objects.iter().map(|object| object_field(bytes, object, base)).collect();
        let objects_start = objects[0].start;
        let objects_end = objects.iter().map(|object| object.end).max().unwrap_or(objects_start);
        let streams = objects.iter().filter(|object| object.stream.is_some()).count();
        fields.push(Field::new("objects", base + objects_start, objects_end - objects_start, format!("{} objects, {streams} streams", objects.len())).with_children(object_fields));
        let files = embedded_files(bytes, &objects);
        if !files.is_empty() {
            let children: Vec<Field> = files
                .iter()
                .map(|(name, index)| {
                    let object = &objects[*index];
                    match &object.stream {
                        Some(stream) => Field::new(name.clone(), base + stream.start, stream.len, format!("object {}, {} ({})", object.number, human_bytes(stream.len as u64), stream.filter.as_deref().unwrap_or("no filter"))),
                        None => Field::new(name.clone(), base + object.start, object.end - object.start, format!("object {}, its stream not found", object.number)),
                    }
                })
                .collect();
            let first = children.iter().map(|field| field.offset).min().unwrap_or(base);
            let last = children.iter().map(Field::end).max().unwrap_or(base);
            fields.push(Field::new("embedded files", first, last - first, files.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>().join(", ")).with_children(children));
        }
        if let Some(xref) = find(bytes, objects_end, b"xref") {
            let trailer = find(bytes, xref, b"trailer");
            let xref_end = trailer.unwrap_or(extent.max(xref));
            fields.push(Field::new("cross-reference table", base + xref, xref_end - xref, format!("{} bytes", xref_end - xref)));
            if let Some(trailer) = trailer {
                let trailer_end = find(bytes, trailer, b"startxref").unwrap_or(bytes.len());
                fields.push(Field::new("trailer", base + trailer, trailer_end - trailer, text_preview(bytes[trailer..trailer_end].trim_ascii(), DICTIONARY_PREVIEW)));
            }
        }
        let extent = fields.iter().map(Field::end).max().map_or(extent, |end| extent.max(end - base));
        let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
        let detail = format!(
            "PDF {version}, {} objects, {streams} streams{}{}",
            objects.len(),
            if names.is_empty() { String::new() } else { format!(", embedded: {}", names.join(", ")) },
            if last_end_of_file.is_some() { "" } else { ", no %%EOF" }
        );
        Some(
            Finding::new("pdf", SOURCE, Category::Document, base, extent)
                .title("PDF document")
                .detail(detail)
                .confidence(if last_end_of_file.is_some() { 1.0 } else { 0.7 })
                .fields(fields),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::{self, Codec};

    /// A small PDF with a page, a compressed content stream and an embedded
    /// file named by a file specification; returns it with the embedded
    /// stream's offset and length.
    fn sample() -> (Vec<u8>, usize, usize) {
        let page = compress::compress(Codec::Zlib, b"BT /F1 12 Tf 72 720 Td (Q3 board) Tj ET").unwrap();
        let csv = compress::compress(Codec::Zlib, b"part,qty\nR1,4\nFLAG{in_the_pdf},1\n").unwrap();
        let mut pdf = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles 3 0 R >> >>\nendobj\n");
        pdf.extend_from_slice(format!("2 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n", page.len()).as_bytes());
        pdf.extend_from_slice(&page);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        pdf.extend_from_slice(b"3 0 obj\n<< /Names [(bom_rev3.csv) 4 0 R] >>\nendobj\n");
        pdf.extend_from_slice(b"4 0 obj\n<< /Type /Filespec /F (bom_rev3.csv) /UF (bom_rev3.csv) /EF << /F 5 0 R >> >>\nendobj\n");
        // The length is indirect, so the stream runs to "endstream".
        pdf.extend_from_slice(b"5 0 obj\n<< /Type /EmbeddedFile /Subtype /text#2Fcsv /Length 6 0 R /Filter /FlateDecode >>\nstream\r\n");
        let csv_at = pdf.len();
        pdf.extend_from_slice(&csv);
        pdf.extend_from_slice(b"\r\nendstream\nendobj\n");
        pdf.extend_from_slice(format!("6 0 obj\n{}\nendobj\n", csv.len()).as_bytes());
        pdf.extend_from_slice(b"xref\n0 7\n0000000000 65535 f \ntrailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");
        (pdf, csv_at, csv.len())
    }

    #[test]
    fn objects_streams_and_an_embedded_file_are_listed_with_their_offsets() {
        let (pdf, csv_at, csv_len) = sample();
        let finding = PdfParser.parse(&pdf, 1000).expect("pdf");
        assert_eq!(finding.len, pdf.len());
        assert_eq!(finding.detail, "PDF 1.7, 6 objects, 2 streams, embedded: bom_rev3.csv");
        let field = |name: &str| finding.fields.iter().find(|field| field.name == name).unwrap_or_else(|| panic!("no {name}"));
        let objects = &field("objects").children;
        assert_eq!(objects[1].name, "object 2 0");
        assert!(objects[1].value.contains("(/FlateDecode)"), "{}", objects[1].value);
        let embedded = &field("embedded files").children[0];
        assert_eq!((embedded.name.as_str(), embedded.offset, embedded.len), ("bom_rev3.csv", 1000 + csv_at, csv_len));
        assert_eq!(embedded.value, format!("object 5, {csv_len} B (/FlateDecode)"));
        let stream = &objects[4].children[1];
        assert_eq!((stream.name.as_str(), stream.offset), ("stream data", 1000 + csv_at));
        assert!(compress::decompress(Codec::Zlib, &pdf[csv_at..csv_at + csv_len], 1 << 20).unwrap().complete, "the field covers exactly the zlib data");
        assert!(field("trailer").value.starts_with("trailer"));
    }

    #[test]
    fn a_stream_containing_endobj_does_not_end_its_object() {
        let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Length 12 >>\nstream\nendobj 2 0 o\nendstream\nendobj\n".to_vec();
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n");
        let finding = PdfParser.parse(&pdf, 0).expect("pdf");
        let objects = &finding.fields[1].children;
        assert_eq!(objects.iter().map(|object| object.name.as_str()).collect::<Vec<_>>(), ["object 1 0", "object 2 0"]);
        assert_eq!(objects[0].children[1].len, 12);
    }

    #[test]
    fn damaged_pdfs_do_not_panic() {
        let (pdf, _, _) = sample();
        for cut in (0..pdf.len()).step_by(7) {
            let _ = PdfParser.parse(&pdf[..cut], 0);
        }
        assert!(PdfParser.parse(b"%PDF-1.4\nno objects here", 0).is_none());
        let _ = PdfParser.parse(b"%PDF-1.4\n1 0 obj << /Length 99999999999999999999 >> stream\n", 0);
        let _ = PdfParser.parse(b"%PDF-1.4\n1 0 obj << /F ((((( /EF << /F 1 0 R", 0);
    }
}
