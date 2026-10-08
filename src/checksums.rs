//! Digests of a selection, and "find the checksum": working out which bytes
//! of a file are a checksum over which other bytes.

use md5::Md5;
use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Common checksums and hashes of one byte range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digests {
    pub crc32: u32,
    pub adler32: u32,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sum8: u8,
    pub sum16: u16,
    pub xor8: u8,
}

/// Compute every digest of `bytes`.
pub fn digests(bytes: &[u8]) -> Digests {
    Digests {
        crc32: crc32(bytes),
        adler32: adler32(bytes),
        md5: hex(&Md5::digest(bytes)),
        sha1: hex(&Sha1::digest(bytes)),
        sha256: hex(&Sha256::digest(bytes)),
        sum8: sum8(bytes),
        sum16: sum16(bytes),
        xor8: bytes.iter().fold(0u8, |acc, b| acc ^ b),
    }
}

/// Shannon entropy in bits per byte.
pub fn entropy(bytes: &[u8]) -> f32 {
    crate::analysis::shannon_entropy(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

pub fn adler32(bytes: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    let (mut a, mut b) = (1u32, 0u32);
    // Reduce every 5552 bytes, the largest run that cannot overflow.
    for chunk in bytes.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MODULUS;
        b %= MODULUS;
    }
    (b << 16) | a
}

pub fn sum8(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

pub fn sum16(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0u16, |acc, &b| acc.wrapping_add(b as u16))
}

pub fn sum32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

/// CRC-16/CCITT-FALSE: polynomial 0x1021, initial 0xFFFF, no reflection.
pub fn crc16_ccitt(bytes: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &byte in bytes {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// CRC-16/ARC: polynomial 0x8005 reflected (0xA001), initial 0.
pub fn crc16_arc(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in bytes {
        crc ^= byte as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xA001 } else { crc >> 1 };
        }
    }
    crc
}

/// A checksum field and the bytes it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChecksumMatch {
    pub algorithm: &'static str,
    /// Document offset of the stored value.
    pub value_offset: usize,
    pub value_len: usize,
    /// "little", "big" or "" for single bytes.
    pub endian: &'static str,
    /// Document offset of the covered bytes.
    pub covered_start: usize,
    pub covered_len: usize,
}

/// Most covered-range tests per call.
const MAX_RANGE_TESTS: usize = 2000;
/// How far into the start and end of the data candidates are tried when the
/// caller gives none.
const EDGE: usize = 64;
/// Covered ranges shorter than this are ignored: tiny ranges match by chance.
const MIN_COVERED: usize = 8;

/// One way a stored value might relate to the data.
#[derive(Clone, Copy)]
struct Algorithm {
    name: &'static str,
    width: usize,
    compute: fn(&[u8]) -> u64,
}

const ALGORITHMS: [Algorithm; 7] = [
    Algorithm { name: "CRC-32", width: 4, compute: |b| crc32(b) as u64 },
    Algorithm { name: "Adler-32", width: 4, compute: |b| adler32(b) as u64 },
    Algorithm { name: "sum32", width: 4, compute: |b| sum32(b) as u64 },
    Algorithm { name: "CRC-16/CCITT", width: 2, compute: |b| crc16_ccitt(b) as u64 },
    Algorithm { name: "CRC-16/ARC", width: 2, compute: |b| crc16_arc(b) as u64 },
    Algorithm { name: "sum16", width: 2, compute: |b| sum16(b) as u64 },
    Algorithm { name: "sum8", width: 1, compute: |b| sum8(b) as u64 },
];

const XOR8: Algorithm = Algorithm { name: "xor8", width: 1, compute: |b| b.iter().fold(0u8, |acc, x| acc ^ x) as u64 };

/// A covered range to test, in local offsets; `zeroed` blanks the value field
/// first (headers often checksum themselves with the field zeroed).
#[derive(Clone, Copy, PartialEq, Eq)]
struct RangeTest {
    start: usize,
    end: usize,
    zeroed: bool,
}

/// Find checksum fields in `bytes` (document offset `base`).
///
/// `candidates` are local offsets of suspected fields; when empty, every
/// 4-aligned offset in the first and last 64 bytes, at and either side of
/// each boundary and before any padding at the end is tried. `boundaries`
/// are local offsets of region edges, which also bound covered ranges.
pub fn find_checksums(bytes: &[u8], base: usize, candidates: &[usize], boundaries: &[usize]) -> Vec<ChecksumMatch> {
    let content_end = content_end(bytes);
    let fields = candidate_fields(bytes.len(), content_end, candidates, boundaries);
    let mut jobs: Vec<(usize, Algorithm, RangeTest)> = Vec::new();
    'outer: for &field in &fields {
        for algorithm in ALGORITHMS.iter().copied().chain(std::iter::once(XOR8)) {
            if field + algorithm.width > bytes.len() {
                continue;
            }
            // One-byte checksums match random data one time in 256, so they
            // are only believed as the last byte of the data (before any
            // padding) or of a region, over the bytes before it.
            let ends_something = [bytes.len(), content_end].contains(&(field + 1)) || boundaries.iter().any(|&b| b == field || b == field + 1);
            if algorithm.width == 1 && !ends_something {
                continue;
            }
            for range in covered_ranges(bytes.len(), field, algorithm.width, boundaries) {
                if algorithm.width == 1 && range.end != field {
                    continue;
                }
                if jobs.len() >= MAX_RANGE_TESTS {
                    break 'outer;
                }
                jobs.push((field, algorithm, range));
            }
        }
    }
    let mut matches: Vec<ChecksumMatch> = jobs
        .par_iter()
        .filter_map(|&(field, algorithm, range)| test_range(bytes, base, field, algorithm, range))
        .flatten()
        .collect();
    matches.sort_by_key(|m| (m.value_offset, m.covered_start, m.covered_len));
    matches.dedup();
    matches
}

/// Where the data ends before a run of padding (zero or 0xFF bytes) at
/// its end; the whole length when there is none, or nothing but padding.
fn content_end(bytes: &[u8]) -> usize {
    let Some(&last) = bytes.last().filter(|&&last| last == 0x00 || last == 0xFF) else { return bytes.len() };
    match bytes.iter().rposition(|&byte| byte != last) {
        Some(position) => position + 1,
        None => bytes.len(),
    }
}

fn candidate_fields(len: usize, content_end: usize, candidates: &[usize], boundaries: &[usize]) -> Vec<usize> {
    let mut fields: Vec<usize> = if candidates.is_empty() {
        let mut fields: Vec<usize> = (0..EDGE.min(len)).step_by(4).collect();
        let tail_start = len.saturating_sub(EDGE) & !3;
        fields.extend((tail_start..len).step_by(4));
        // Single-byte and 2-byte trailers are often unaligned at the very
        // end, or at the end before padding.
        for end in [len, content_end] {
            fields.extend([end.saturating_sub(1), end.saturating_sub(2), end.saturating_sub(4)]);
        }
        // A value may start at a boundary or end at one.
        for &boundary in boundaries {
            fields.extend([boundary.saturating_sub(1), boundary, boundary + 4]);
        }
        fields
    } else {
        candidates.to_vec()
    };
    fields.retain(|&f| f < len);
    fields.sort_unstable();
    fields.dedup();
    fields
}

fn covered_ranges(len: usize, field: usize, width: usize, boundaries: &[usize]) -> Vec<RangeTest> {
    let field_end = field + width;
    let mut ranges = vec![
        RangeTest { start: 0, end: field, zeroed: false },
        RangeTest { start: field_end, end: len, zeroed: false },
        RangeTest { start: 0, end: len, zeroed: true },
    ];
    // The region between the boundaries either side of the field.
    let previous = boundaries.iter().copied().filter(|&b| b <= field).max().unwrap_or(0);
    let next = boundaries.iter().copied().filter(|&b| b >= field_end).min().unwrap_or(len);
    ranges.push(RangeTest { start: previous, end: field, zeroed: false });
    ranges.push(RangeTest { start: field_end, end: next, zeroed: false });
    ranges.push(RangeTest { start: previous, end: next, zeroed: true });
    ranges.retain(|r| r.end > r.start && r.end - r.start >= MIN_COVERED);
    ranges.sort_by_key(|r| (r.start, r.end, r.zeroed));
    ranges.dedup();
    ranges
}

fn test_range(bytes: &[u8], base: usize, field: usize, algorithm: Algorithm, range: RangeTest) -> Option<Vec<ChecksumMatch>> {
    let stored = &bytes[field..field + algorithm.width];
    // A stored value of all zeroes or all ones matches far too often.
    if stored.iter().all(|&b| b == 0) || stored.iter().all(|&b| b == 0xFF) {
        return None;
    }
    let computed = if range.zeroed {
        let mut copy = bytes[range.start..range.end].to_vec();
        if field >= range.start && field + algorithm.width <= range.end {
            copy[field - range.start..field - range.start + algorithm.width].fill(0);
        }
        (algorithm.compute)(&copy)
    } else {
        (algorithm.compute)(&bytes[range.start..range.end])
    };
    let mut found = Vec::new();
    let endians: &[(&'static str, bool)] = if algorithm.width == 1 { &[("", true)] } else { &[("little", true), ("big", false)] };
    for &(endian, little) in endians {
        if read_value(stored, little) == computed {
            found.push(ChecksumMatch {
                algorithm: algorithm.name,
                value_offset: base + field,
                value_len: algorithm.width,
                endian,
                covered_start: base + range.start,
                covered_len: range.end - range.start,
            });
        }
    }
    (!found.is_empty()).then_some(found)
}

fn read_value(bytes: &[u8], little: bool) -> u64 {
    let fold = |acc: u64, b: &u8| (acc << 8) | *b as u64;
    if little { bytes.iter().rev().fold(0, fold) } else { bytes.iter().fold(0, fold) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn digests_of_hello_match_known_values() {
        let d = digests(b"hello");
        assert_eq!(d.crc32, 0x3610_a686);
        assert_eq!(d.adler32, 0x062c_0215);
        assert_eq!(d.md5, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(d.sha1, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
        assert_eq!(d.sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(d.sum8, b"hello".iter().fold(0u8, |a, b| a.wrapping_add(*b)));
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
        assert_eq!(crc16_arc(b"123456789"), 0xBB3D);
    }

    #[test]
    fn finds_a_header_crc_over_the_payload_after_it() {
        let payload = noise(300, 7);
        let mut file = b"HDR1".to_vec();
        file.extend_from_slice(&crc32(&payload).to_le_bytes());
        file.extend_from_slice(&payload);
        let found = find_checksums(&file, 1000, &[], &[]);
        assert!(
            found.iter().any(|m| m.algorithm == "CRC-32" && m.value_offset == 1004 && m.endian == "little" && m.covered_start == 1008 && m.covered_len == 300),
            "{found:?}"
        );
    }

    #[test]
    fn finds_trailer_crc_and_sum8_over_everything_before_them() {
        let body = noise(500, 9);
        let mut file = body.clone();
        file.extend_from_slice(&crc32(&body).to_be_bytes());
        let found = find_checksums(&file, 0, &[], &[]);
        assert!(found.iter().any(|m| m.algorithm == "CRC-32" && m.value_offset == 500 && m.endian == "big" && m.covered_len == 500), "{found:?}");

        let mut file = body.clone();
        let total = sum8(&body);
        file.push(if total == 0 { 1 } else { total });
        if total != 0 {
            let found = find_checksums(&file, 0, &[], &[]);
            assert!(found.iter().any(|m| m.algorithm == "sum8" && m.value_offset == 500 && m.covered_len == 500), "{found:?}");
        }
    }

    #[test]
    fn finds_a_header_checksum_computed_with_its_field_zeroed() {
        let mut file = b"IMG!".to_vec();
        file.extend_from_slice(&[0u8; 4]);
        file.extend_from_slice(&noise(200, 11));
        let value = crc32(&file);
        file[4..8].copy_from_slice(&value.to_le_bytes());
        let found = find_checksums(&file, 0, &[4], &[]);
        assert!(found.iter().any(|m| m.algorithm == "CRC-32" && m.value_offset == 4 && m.covered_start == 0 && m.covered_len == file.len()), "{found:?}");
    }

    /// A remote's frame: sync, serial, button, counter and the sum of them.
    const FRAME: [u8; 9] = [0xAA, 0x2D, 0x74, 0xB5, 0x27, 0x01, 0x19, 0x52, 0x93];

    #[test]
    fn a_sum_byte_followed_by_padding_is_found() {
        let mut data = FRAME.to_vec();
        data.extend([0, 0, 0, 0]);
        let found = find_checksums(&data, 0, &[], &[]);
        assert!(found.iter().any(|m| m.algorithm == "sum8" && m.value_offset == 8 && m.covered_start == 0 && m.covered_len == 8), "{found:?}");
    }

    #[test]
    fn a_sum_byte_ending_at_a_boundary_is_found_whatever_follows() {
        let mut data = FRAME.to_vec();
        data.extend([0xFF, 0xEE]);
        for boundaries in [[8], [9]] {
            let found = find_checksums(&data, 0, &[], &boundaries);
            assert!(found.iter().any(|m| m.algorithm == "sum8" && m.value_offset == 8 && m.covered_len == 8), "{boundaries:?}: {found:?}");
        }
    }

    #[test]
    fn noise_yields_no_matches() {
        let data = noise(4096, 0xC0FFEE);
        let found = find_checksums(&data, 0, &[], &[]);
        assert!(found.is_empty(), "{found:?}");
    }
}
