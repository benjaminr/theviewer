//! Unpacking downloaded sample captures: gzip, bzip2 and xz streams, zip
//! archives (stored or deflated members) and tar files, to a size cap.

use std::io::{Read, Write};

/// What one download unpacked to.
#[derive(Debug, Default, PartialEq)]
pub struct Unpacked {
    /// `(name, bytes)` for each file found.
    pub files: Vec<(String, Vec<u8>)>,
    /// Why some or all of the download could not be unpacked.
    pub problems: Vec<String>,
}

const ZIP_LOCAL_HEADER: u32 = 0x0403_4B50;
const ZIP_CENTRAL_HEADER: u32 = 0x0201_4B50;
const ZIP_END_OF_DIRECTORY: u32 = 0x0605_4B50;
const ZIP_END_LEN: usize = 22;
/// The end-of-directory record may be followed by a comment this long.
const ZIP_MAX_COMMENT: usize = 0xFFFF;
const ZIP_STORED: u16 = 0;
const ZIP_DEFLATED: u16 = 8;
const TAR_BLOCK: usize = 512;
const TAR_REGULAR_FILE: [u8; 2] = [b'0', 0];

/// Unpack `bytes`, downloaded as `name`, keeping at most `limit` bytes of
/// any one file. Names ending in a compression suffix are decompressed (and
/// an inner `.tar` unpacked); anything else is returned as it is.
pub fn unpack(name: &str, bytes: Vec<u8>, limit: usize) -> Unpacked {
    let lower = name.to_lowercase();
    let mut unpacked = Unpacked::default();
    let decompressed = if let Some(stem) = lower.strip_suffix(".tgz") {
        decompress_gzip(&bytes, limit).map(|data| (format!("{}.tar", &name[..stem.len()]), data))
    } else if let Some(stem) = lower.strip_suffix(".gz") {
        decompress_gzip(&bytes, limit).map(|data| (name[..stem.len()].to_string(), data))
    } else if let Some(stem) = lower.strip_suffix(".bz2") {
        decompress_bzip2(&bytes, limit).map(|data| (name[..stem.len()].to_string(), data))
    } else if let Some(stem) = lower.strip_suffix(".xz") {
        decompress_xz(&bytes, limit).map(|data| (name[..stem.len()].to_string(), data))
    } else if lower.ends_with(".zip") {
        let (files, problems) = unzip(&bytes, limit);
        unpacked.problems = problems;
        for (member, data) in files {
            let inner = unpack(&member, data, limit);
            unpacked.files.extend(inner.files.into_iter().map(|(inner_name, data)| (format!("{}__{inner_name}", strip_extension(name)), data)));
            unpacked.problems.extend(inner.problems);
        }
        return unpacked;
    } else if lower.ends_with(".tar") {
        let (files, problems) = untar(&bytes, limit);
        unpacked.problems = problems;
        unpacked.files = files.into_iter().map(|(member, data)| (format!("{}__{member}", strip_extension(name)), data)).collect();
        return unpacked;
    } else if lower.ends_with(".7z") || lower.ends_with(".rar") {
        unpacked.problems.push(format!("{name}: {} archives cannot be opened here", lower.rsplit('.').next().unwrap_or_default()));
        return unpacked;
    } else {
        unpacked.files.push((name.to_string(), bytes));
        return unpacked;
    };
    match decompressed {
        Ok((inner_name, data)) if inner_name.to_lowercase().ends_with(".tar") => {
            let inner = unpack(&inner_name, data, limit);
            unpacked.files = inner.files;
            unpacked.problems.extend(inner.problems);
        }
        Ok((inner_name, data)) => unpacked.files.push((inner_name, data)),
        Err(problem) => unpacked.problems.push(format!("{name}: {problem}")),
    }
    unpacked
}

fn strip_extension(name: &str) -> &str {
    name.rsplit_once('.').map_or(name, |(stem, _)| stem)
}

/// Read all of `reader`, failing once more than `limit` bytes come out.
fn read_limited(reader: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut out).map_err(|error| error.to_string())?;
    if out.len() > limit {
        return Err(format!("unpacks to more than {limit} bytes"));
    }
    Ok(out)
}

fn decompress_gzip(bytes: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    read_limited(flate2::read::MultiGzDecoder::new(bytes), limit)
}

fn decompress_bzip2(bytes: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    read_limited(bzip2::read::BzDecoder::new(bytes), limit)
}

fn decompress_xz(bytes: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut writer = LimitedWriter { data: Vec::new(), limit };
    lzma_rs::xz_decompress(&mut std::io::BufReader::new(bytes), &mut writer).map_err(|error| error.to_string())?;
    Ok(writer.data)
}

/// A writer that refuses to grow past a limit.
struct LimitedWriter {
    data: Vec<u8>,
    limit: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.data.len() + buffer.len() > self.limit {
            return Err(std::io::Error::other(format!("unpacks to more than {} bytes", self.limit)));
        }
        self.data.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The files of a zip archive, read through its central directory. Members
/// that are directories, encrypted, or compressed other than by deflate are
/// reported as problems.
pub fn unzip(bytes: &[u8], limit: usize) -> (Vec<(String, Vec<u8>)>, Vec<String>) {
    let mut files = Vec::new();
    let mut problems = Vec::new();
    let search_from = bytes.len().saturating_sub(ZIP_END_LEN + ZIP_MAX_COMMENT);
    let Some(end) = (search_from..bytes.len().saturating_sub(ZIP_END_LEN - 1)).rev().find(|&at| u32_at(bytes, at) == Some(ZIP_END_OF_DIRECTORY)) else {
        problems.push("no zip directory found".to_string());
        return (files, problems);
    };
    let entries = u16_at(bytes, end + 10).unwrap_or(0) as usize;
    let mut at = u32_at(bytes, end + 16).unwrap_or(u32::MAX) as usize;
    for _ in 0..entries {
        if u32_at(bytes, at) != Some(ZIP_CENTRAL_HEADER) {
            problems.push(format!("the zip directory is damaged at {at:#x}"));
            break;
        }
        let (Some(flags), Some(method), Some(compressed), Some(name_len), Some(extra_len), Some(comment_len), Some(local)) = (
            u16_at(bytes, at + 8),
            u16_at(bytes, at + 10),
            u32_at(bytes, at + 20),
            u16_at(bytes, at + 28),
            u16_at(bytes, at + 30),
            u16_at(bytes, at + 32),
            u32_at(bytes, at + 42),
        ) else {
            problems.push("the zip directory is cut short".to_string());
            break;
        };
        let name = String::from_utf8_lossy(bytes.get(at + 46..at + 46 + name_len as usize).unwrap_or_default()).into_owned();
        at += 46 + name_len as usize + extra_len as usize + comment_len as usize;
        if name.ends_with('/') {
            continue;
        }
        match zip_member(bytes, local as usize, flags, method, compressed as usize, limit) {
            Ok(data) => files.push((name.rsplit('/').next().unwrap_or(&name).to_string(), data)),
            Err(problem) => problems.push(format!("{name}: {problem}")),
        }
    }
    (files, problems)
}

fn zip_member(bytes: &[u8], local: usize, flags: u16, method: u16, compressed: usize, limit: usize) -> Result<Vec<u8>, String> {
    const ENCRYPTED: u16 = 1;
    if flags & ENCRYPTED != 0 {
        return Err("encrypted".to_string());
    }
    if u32_at(bytes, local) != Some(ZIP_LOCAL_HEADER) {
        return Err("its local header is missing".to_string());
    }
    let name_len = u16_at(bytes, local + 26).unwrap_or(0) as usize;
    let extra_len = u16_at(bytes, local + 28).unwrap_or(0) as usize;
    let start = local + 30 + name_len + extra_len;
    let data = bytes.get(start..start.saturating_add(compressed)).ok_or("its data runs past the end of the archive")?;
    match method {
        ZIP_STORED if data.len() <= limit => Ok(data.to_vec()),
        ZIP_STORED => Err(format!("larger than {limit} bytes")),
        ZIP_DEFLATED => read_limited(flate2::read::DeflateDecoder::new(data), limit),
        other => Err(format!("compression method {other} is not supported")),
    }
}

/// The regular files of a tar archive.
pub fn untar(bytes: &[u8], limit: usize) -> (Vec<(String, Vec<u8>)>, Vec<String>) {
    let mut files = Vec::new();
    let mut problems = Vec::new();
    let mut at = 0;
    while let Some(header) = bytes.get(at..at + TAR_BLOCK) {
        if header.iter().all(|&byte| byte == 0) {
            break;
        }
        let text = |range: std::ops::Range<usize>| String::from_utf8_lossy(&header[range]).trim_end_matches('\0').trim().to_string();
        let Ok(size) = usize::from_str_radix(&text(124..136), 8) else {
            problems.push(format!("the tar header at {at:#x} has no readable size"));
            break;
        };
        let prefix = text(345..500);
        let name = text(0..100);
        let name = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        let data_at = at + TAR_BLOCK;
        if TAR_REGULAR_FILE.contains(&header[156]) {
            match bytes.get(data_at..data_at.saturating_add(size)) {
                Some(_) if size > limit => problems.push(format!("{name}: larger than {limit} bytes")),
                Some(data) => files.push((name.rsplit('/').next().unwrap_or(&name).to_string(), data.to_vec())),
                None => {
                    problems.push(format!("{name}: cut short"));
                    break;
                }
            }
        }
        at = data_at.saturating_add(size.div_ceil(TAR_BLOCK) * TAR_BLOCK);
    }
    (files, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 1 << 20;

    /// A zip archive with one stored member, built field by field.
    fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
        let crc = crc32fast::hash(data);
        let mut zip = Vec::new();
        let local = |zip: &mut Vec<u8>| {
            zip.extend_from_slice(&ZIP_LOCAL_HEADER.to_le_bytes());
            zip.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // version, flags, method, time, date
            zip.extend_from_slice(&crc.to_le_bytes());
            zip.extend_from_slice(&(data.len() as u32).to_le_bytes());
            zip.extend_from_slice(&(data.len() as u32).to_le_bytes());
            zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
            zip.extend_from_slice(name.as_bytes());
        };
        local(&mut zip);
        zip.extend_from_slice(data);
        let directory_at = zip.len();
        zip.extend_from_slice(&ZIP_CENTRAL_HEADER.to_le_bytes());
        zip.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // made by, needed, flags, method, time, date
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(data.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(data.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&[0; 12]); // extra, comment, disk, attributes
        zip.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        zip.extend_from_slice(name.as_bytes());
        let directory_len = zip.len() - directory_at;
        zip.extend_from_slice(&ZIP_END_OF_DIRECTORY.to_le_bytes());
        zip.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        zip.extend_from_slice(&(directory_len as u32).to_le_bytes());
        zip.extend_from_slice(&(directory_at as u32).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip
    }

    /// A tar archive with one regular file.
    fn tar_of(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; TAR_BLOCK];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[156] = b'0';
        let mut tar = header.to_vec();
        tar.extend_from_slice(data);
        tar.resize(tar.len().div_ceil(TAR_BLOCK) * TAR_BLOCK, 0);
        tar.extend_from_slice(&[0; 2 * TAR_BLOCK]);
        tar
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        crate::compress::compress(crate::compress::Codec::Gzip, data).unwrap()
    }

    #[test]
    fn a_gzipped_capture_unpacks_under_its_inner_name() {
        let unpacked = unpack("trace.pcap.gz", gzip(b"capture bytes"), LIMIT);
        assert_eq!(unpacked.files, vec![("trace.pcap".to_string(), b"capture bytes".to_vec())]);
        assert!(unpacked.problems.is_empty());
    }

    #[test]
    fn a_zip_member_and_a_tarball_member_are_found() {
        let unpacked = unpack("bundle.zip", stored_zip("dir/inner.pcapng", b"pcapng bytes"), LIMIT);
        assert_eq!(unpacked.files, vec![("bundle__inner.pcapng".to_string(), b"pcapng bytes".to_vec())]);
        let unpacked = unpack("set.tgz", gzip(&tar_of("set/one.cap", b"one")), LIMIT);
        assert_eq!(unpacked.files, vec![("set__one.cap".to_string(), b"one".to_vec())], "{:?}", unpacked.problems);
    }

    #[test]
    fn a_decompression_bomb_and_an_unknown_archive_are_refused_with_a_reason() {
        let unpacked = unpack("big.pcap.gz", gzip(&vec![0u8; 4096]), 1024);
        assert!(unpacked.files.is_empty());
        assert!(unpacked.problems[0].contains("more than 1024 bytes"), "{:?}", unpacked.problems);
        let unpacked = unpack("set.7z", vec![1, 2, 3], LIMIT);
        assert!(unpacked.problems[0].contains("7z"), "{:?}", unpacked.problems);
        let (files, problems) = unzip(b"not a zip at all", LIMIT);
        assert!(files.is_empty() && problems[0].contains("no zip directory"));
    }

    #[test]
    fn a_plain_capture_is_returned_unchanged() {
        assert_eq!(unpack("plain.pcap", b"abc".to_vec(), LIMIT).files, vec![("plain.pcap".to_string(), b"abc".to_vec())]);
    }
}
