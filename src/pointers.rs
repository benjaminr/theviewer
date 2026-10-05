//! Finding values that point at other places in the file, so the viewer can
//! draw them as arrows: tables of contents, linked lists, offset tables.
//!
//! The heuristics are deliberately conservative, because almost any number
//! is "a valid offset" in a large enough file:
//!
//! 1. Only aligned 4- and 8-byte values are considered.
//! 2. A value must map to a file offset: directly (`0 < value < document_len`)
//!    or through an executable's address map.
//! 3. Tiny values (below 256) are ignored; they are usually counts or flags.
//! 4. Runs of three or more values with a constant small step (below 16) are
//!    counters or indices, not pointers, and are dropped.
//! 5. What survives must either cluster (three or more pointers within 64
//!    bytes, as in a table) or land somewhere recognisable inside the window:
//!    a known magic, or the first non-zero byte after zero padding.

/// One value that points somewhere else in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    /// Document offset of the stored value.
    pub from: usize,
    /// 4 or 8.
    pub width: usize,
    /// Document offset the value points at.
    pub to: usize,
    pub value: u64,
}

/// Most pointers returned per call.
const MAX_POINTERS: usize = 10_000;
/// Values below this are counts or flags far more often than offsets.
const MIN_VALUE: u64 = 256;
/// A step smaller than this between neighbours marks a counter.
const COUNTER_STEP: u64 = 16;
/// Pointers this close together, and at least this many of them, form a table.
const CLUSTER_SPAN: usize = 64;
const CLUSTER_SIZE: usize = 3;
/// Magic numbers that make a target recognisable.
const KNOWN_TARGETS: [&[u8]; 4] = [b"PK", b"\x7FELF", b"\x89PNG", b"MZ"];

/// Find pointers among the values in `window` (document offset
/// `window_base`). `map` converts a value to a file offset for executables;
/// without it values are taken as plain offsets. Targets closer than
/// `min_target_gap` to the value itself are ignored.
pub fn find_pointers(
    window: &[u8],
    window_base: usize,
    document_len: usize,
    map: Option<&dyn Fn(u64) -> Option<usize>>,
    little_endian: bool,
    min_target_gap: usize,
) -> Vec<Pointer> {
    let resolve = |value: u64| -> Option<usize> {
        if value < MIN_VALUE {
            return None;
        }
        match map {
            Some(map) => map(value),
            None => (value < document_len as u64).then_some(value as usize),
        }
    };
    let read = |at: usize, width: usize| -> u64 {
        let bytes = &window[at..at + width];
        let fold = |acc: u64, b: &u8| (acc << 8) | *b as u64;
        if little_endian { bytes.iter().rev().fold(0, fold) } else { bytes.iter().fold(0, fold) }
    };

    let mut candidates = Vec::new();
    for width in [8usize, 4] {
        let mut at = align_up(window_base, width) - window_base;
        while at + width <= window.len() {
            let value = read(at, width);
            if let Some(to) = resolve(value) {
                let from = window_base + at;
                if from.abs_diff(to) >= min_target_gap.max(1) {
                    candidates.push(Pointer { from, width, to, value });
                }
            }
            at += width;
        }
    }
    let candidates = prefer_widths(candidates, window, window_base, &resolve, &read);
    let candidates = drop_counters(candidates);
    let mut pointers: Vec<Pointer> = candidates
        .iter()
        .copied()
        .filter(|pointer| clustered(&candidates, pointer) || recognisable_target(window, window_base, pointer.to))
        .collect();
    pointers.sort_by_key(|p| p.from);
    pointers.truncate(MAX_POINTERS);
    pointers
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

/// An 8-byte slot is two 4-byte slots too. Keep the 4-byte reading when the
/// upper half is itself a plausible pointer (a table of 32-bit offsets), and
/// the 8-byte reading otherwise.
fn prefer_widths(
    candidates: Vec<Pointer>,
    window: &[u8],
    window_base: usize,
    resolve: &dyn Fn(u64) -> Option<usize>,
    read: &dyn Fn(usize, usize) -> u64,
) -> Vec<Pointer> {
    let wide: std::collections::HashSet<usize> = candidates.iter().filter(|p| p.width == 8).map(|p| p.from).collect();
    candidates
        .into_iter()
        .filter(|pointer| {
            let local = pointer.from - window_base;
            let upper_is_pointer = |slot: usize| slot + 8 <= window.len() && resolve(read(slot + 4, 4)).is_some();
            match pointer.width {
                8 => !upper_is_pointer(local),
                // A 4-byte reading at the start of an accepted 8-byte slot is redundant.
                _ => !(wide.contains(&pointer.from) && !upper_is_pointer(local)),
            }
        })
        .collect()
}

/// Drop runs of three or more consecutive same-width values whose step is
/// constant and small: those are counters or indices.
fn drop_counters(mut candidates: Vec<Pointer>) -> Vec<Pointer> {
    candidates.sort_by_key(|p| (p.width, p.from));
    let mut keep = vec![true; candidates.len()];
    let mut run_start = 0;
    for index in 1..=candidates.len() {
        let continues = index < candidates.len() && {
            let (previous, current) = (candidates[index - 1], candidates[index]);
            let adjacent = current.width == previous.width && current.from == previous.from + previous.width;
            let step = current.value.abs_diff(previous.value);
            let same_step = index - run_start < 2 || step == candidates[index - 1].value.abs_diff(candidates[index - 2].value);
            adjacent && step < COUNTER_STEP && same_step
        };
        if !continues {
            if index - run_start >= 3 {
                keep[run_start..index].fill(false);
            }
            run_start = index;
        }
    }
    candidates.into_iter().zip(keep).filter_map(|(p, k)| k.then_some(p)).collect()
}

fn clustered(candidates: &[Pointer], pointer: &Pointer) -> bool {
    candidates
        .iter()
        .filter(|other| other.width == pointer.width && other.from.abs_diff(pointer.from) < CLUSTER_SPAN)
        .count()
        >= CLUSTER_SIZE
}

/// Whether the target, if inside the window, starts with a known magic or is
/// the first non-zero byte after zero padding on a 4-byte boundary.
fn recognisable_target(window: &[u8], window_base: usize, to: usize) -> bool {
    if to < window_base || to >= window_base + window.len() {
        return false;
    }
    let local = to - window_base;
    let rest = &window[local..];
    if KNOWN_TARGETS.iter().any(|magic| rest.starts_with(magic)) {
        return true;
    }
    to.is_multiple_of(4) && local > 0 && window[local - 1] == 0 && window[local] != 0
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
    fn finds_every_entry_of_an_offset_table() {
        // Header, then 8 u32 offsets, then 8 records of 40 bytes.
        let mut file = b"TBL1".to_vec();
        file.extend_from_slice(&[0u8; 12]);
        let table_at = file.len();
        // Records start past 256 so every offset is above the tiny-value cut-off.
        let records_at = 512;
        for k in 0..8u32 {
            file.extend_from_slice(&(records_at as u32 + k * 40).to_le_bytes());
        }
        file.resize(records_at, 0);
        for k in 0..8u8 {
            let mut record = vec![k + 1; 40];
            record[0] = b'R';
            file.extend_from_slice(&record);
        }
        let len = file.len();
        let pointers = find_pointers(&file, 0, len, None, true, 8);
        let from_table: Vec<&Pointer> = pointers.iter().filter(|p| p.from >= table_at && p.from < table_at + 32).collect();
        assert_eq!(from_table.len(), 8, "{pointers:?}");
        for (k, pointer) in from_table.iter().enumerate() {
            assert_eq!(pointer.width, 4);
            assert_eq!(pointer.to, records_at + k * 40);
        }
    }

    #[test]
    fn noise_produces_very_few_pointers() {
        let data = noise(64 * 1024, 0xABCD_1234);
        let pointers = find_pointers(&data, 0, data.len(), None, true, 8);
        let words = data.len() / 4;
        assert!(pointers.len() * 200 < words, "{} pointers in {words} words", pointers.len());
    }

    #[test]
    fn counter_runs_are_not_pointers() {
        let mut data = vec![0u8; 64];
        for k in 0..16u32 {
            data.extend_from_slice(&(1000 + k).to_le_bytes());
        }
        data.resize(4096, 0);
        let pointers = find_pointers(&data, 0, data.len(), None, true, 8);
        assert!(pointers.is_empty(), "{pointers:?}");
    }

    #[test]
    fn address_maps_and_recognisable_targets_are_used() {
        // A lone pointer through an address map to an ELF magic.
        let mut data = vec![0u8; 256];
        data[200..204].copy_from_slice(b"\x7FELF");
        data[16..24].copy_from_slice(&0x4000_0000_00C8u64.to_le_bytes());
        let map = |address: u64| (address >= 0x4000_0000_0000).then(|| (address - 0x4000_0000_0000) as usize);
        let pointers = find_pointers(&data, 0, data.len(), Some(&map), true, 8);
        assert_eq!(pointers, vec![Pointer { from: 16, width: 8, to: 200, value: 0x4000_0000_00C8 }]);
    }
}
