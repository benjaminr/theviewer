//! FAT12, FAT16 and FAT32 volumes, as on USB sticks and SD cards: a boot
//! sector whose BIOS parameter block gives the geometry, one or more file
//! allocation tables chaining clusters together, and directories of 32-byte
//! entries, long names stored as runs of entries before the short one.
//!
//! Deleted entries (first byte 0xE5) are listed too. Deleting a file frees
//! its cluster chain but leaves the data in place, so a deleted file is
//! recovered on the assumption that its clusters were contiguous, and says
//! so in its note.

use std::collections::HashSet;
use std::sync::Arc;

use super::{Allowance, Entry, EntryKind, EntryRecord, Filesystem, FsKind, MAX_DIRECTORY_DEPTH, join_path, le_u16, le_u32, slice_at, take_content};

/// Boot sectors are looked for at each multiple of this, which covers every
/// partition an MBR or GPT can describe.
pub(super) const SCAN_ALIGNMENT: usize = 512;
const BOOT_SECTOR_LEN: usize = 512;
const DIRECTORY_ENTRY_LEN: usize = 32;
/// FAT32 is chosen from this many clusters up, FAT16 from `FAT16_MIN_CLUSTERS`.
const FAT16_MIN_CLUSTERS: u32 = 4085;
const FAT32_MIN_CLUSTERS: u32 = 65_525;
/// Largest cluster read: 256 KiB, beyond what any formatter writes.
const MAX_CLUSTER_BYTES: usize = 256 * 1024;

/// A directory entry's first byte when the entry was deleted.
const DELETED_MARK: u8 = 0xE5;
/// A first byte standing for a real 0xE5 (a Kanji lead byte).
const ESCAPED_E5: u8 = 0x05;
/// Shown for the first character of a deleted short name, which is lost.
const LOST_CHARACTER: char = '_';

/// Directory entry attribute bits.
mod attribute {
    pub const VOLUME_LABEL: u8 = 0x08;
    pub const DIRECTORY: u8 = 0x10;
    /// Read-only, hidden, system and volume label together: a long-name part.
    pub const LONG_NAME: u8 = 0x0F;
}

/// Note on a deleted file whose content was recovered.
pub const NOTE_RECOVERED: &str = "deleted; recovered, contiguous assumption";

/// Which FAT variant a volume is, decided by its cluster count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

impl FatType {
    pub fn label(self) -> &'static str {
        match self {
            FatType::Fat12 => "FAT12",
            FatType::Fat16 => "FAT16",
            FatType::Fat32 => "FAT32",
        }
    }

    /// The smallest table value marking the end of a chain.
    fn end_of_chain(self) -> u32 {
        match self {
            FatType::Fat12 => 0xFF8,
            FatType::Fat16 => 0xFFF8,
            FatType::Fat32 => 0x0FFF_FFF8,
        }
    }
}

/// A volume's geometry from its boot sector, with the offsets it implies.
/// Offsets are from the start of the volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub fat_type: FatType,
    pub bytes_per_sector: usize,
    pub sectors_per_cluster: usize,
    pub reserved_sectors: usize,
    pub fat_count: usize,
    /// Slots in the fixed root directory (zero on FAT32).
    pub root_entries: usize,
    pub total_sectors: usize,
    pub sectors_per_fat: usize,
    /// Sectors before the volume on its disk, as the boot sector records.
    pub hidden_sectors: u32,
    pub media: u8,
    /// The volume serial number, when the extended boot signature is there.
    pub serial: Option<u32>,
    /// Where the serial number is in the boot sector.
    pub serial_at: usize,
    /// FAT32's root directory cluster.
    pub root_cluster: u32,
    /// Data clusters, numbered from 2.
    pub clusters: u32,
    pub fat_offset: usize,
    pub root_offset: usize,
    /// Bytes of the fixed root directory (zero on FAT32).
    pub root_len: usize,
    pub data_offset: usize,
}

impl Geometry {
    pub fn cluster_bytes(&self) -> usize {
        self.bytes_per_sector * self.sectors_per_cluster
    }

    pub fn fat_len(&self) -> usize {
        self.sectors_per_fat * self.bytes_per_sector
    }

    pub fn volume_len(&self) -> usize {
        self.total_sectors * self.bytes_per_sector
    }

    /// Offset of `cluster`'s first byte in the volume.
    pub fn cluster_offset(&self, cluster: u32) -> usize {
        self.data_offset + (cluster as usize).saturating_sub(2) * self.cluster_bytes()
    }

    fn is_data_cluster(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster < self.clusters.saturating_add(2)
    }
}

/// Read the geometry from a boot sector, refusing one whose numbers do not
/// describe a FAT volume. The type string at 54 or 82 is only a label, so
/// the type is decided by the cluster count, as the specification says.
pub fn geometry(boot: &[u8]) -> Result<Geometry, String> {
    let sector = slice_at(boot, 0, BOOT_SECTOR_LEN).ok_or("boot sector is truncated")?;
    if !((sector[0] == 0xEB && sector[2] == 0x90) || sector[0] == 0xE9) {
        return Err("no boot jump".to_string());
    }
    if sector[510..512] != [0x55, 0xAA] {
        return Err("no 55 AA signature".to_string());
    }
    let read16 = |at| le_u16(sector, at).map_or(0, usize::from);
    let read32 = |at| le_u32(sector, at).unwrap_or(0);
    let bytes_per_sector = read16(11);
    let sectors_per_cluster = sector[13] as usize;
    let reserved_sectors = read16(14);
    let fat_count = sector[16] as usize;
    let root_entries = read16(17);
    let total_sectors = match read16(19) {
        0 => read32(32) as usize,
        small => small,
    };
    let media = sector[21];
    let sectors_per_fat = match read16(22) {
        0 => read32(36) as usize,
        small => small,
    };
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(format!("implausible sector size {bytes_per_sector}"));
    }
    if !sectors_per_cluster.is_power_of_two() || sectors_per_cluster * bytes_per_sector > MAX_CLUSTER_BYTES {
        return Err(format!("implausible sectors per cluster {sectors_per_cluster}"));
    }
    if reserved_sectors == 0 || !(1..=4).contains(&fat_count) || media < 0xF0 || sectors_per_fat == 0 || total_sectors == 0 {
        return Err("the BIOS parameter block does not describe a FAT volume".to_string());
    }
    let root_len = root_entries * DIRECTORY_ENTRY_LEN;
    let root_sectors = root_len.div_ceil(bytes_per_sector);
    let fat_offset = reserved_sectors * bytes_per_sector;
    let root_offset = fat_offset + fat_count * sectors_per_fat * bytes_per_sector;
    let data_offset = root_offset + root_sectors * bytes_per_sector;
    let metadata_sectors = reserved_sectors + fat_count * sectors_per_fat + root_sectors;
    let data_sectors = total_sectors.checked_sub(metadata_sectors).filter(|&sectors| sectors > 0).ok_or("the tables fill the whole volume")?;
    let clusters = u32::try_from(data_sectors / sectors_per_cluster).map_err(|_| "too many clusters")?;
    let fat_type = if clusters < FAT16_MIN_CLUSTERS {
        FatType::Fat12
    } else if clusters < FAT32_MIN_CLUSTERS {
        FatType::Fat16
    } else {
        FatType::Fat32
    };
    if (fat_type == FatType::Fat32) != (root_entries == 0) {
        return Err(format!("{} clusters make this {}, but it has {root_entries} root directory slots", clusters, fat_type.label()));
    }
    let (signature_at, serial_at) = if fat_type == FatType::Fat32 { (66, 67) } else { (38, 39) };
    let serial = matches!(sector[signature_at], 0x28 | 0x29).then(|| read32(serial_at));
    Ok(Geometry {
        fat_type,
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        fat_count,
        root_entries,
        total_sectors,
        sectors_per_fat,
        hidden_sectors: read32(28),
        media,
        serial,
        serial_at,
        root_cluster: if fat_type == FatType::Fat32 { read32(44) } else { 0 },
        clusters,
        fat_offset,
        root_offset,
        root_len,
        data_offset,
    })
}

/// Read the FAT volume at the start of `image` (at `base` in the scanned
/// data).
pub(super) fn read(image: &[u8], base: usize, allowance: &mut Allowance) -> Result<Filesystem, String> {
    let geometry = geometry(image)?;
    let len = geometry.volume_len().min(image.len());
    let image = &image[..len];
    let fat = slice_at(image, geometry.fat_offset, geometry.fat_len()).ok_or("the first FAT is cut off")?;
    let mut problems = Vec::new();
    if len < geometry.volume_len() {
        problems.push(format!("volume is truncated: {len} of {} bytes present", geometry.volume_len()));
    }
    let mut walker = Walker {
        image,
        base,
        geometry: &geometry,
        fat,
        entries: Vec::new(),
        paths: HashSet::new(),
        visited: HashSet::new(),
        max_entries: allowance.max_entries(),
        volume_label: None,
        problems,
    };
    let root = walker.root_directory();
    walker.walk_directory(&root, "", 0, allowance);
    let label = walker.volume_label.clone().unwrap_or_default();
    let serial = geometry.serial.map(|serial| format!(", serial {:04X}-{:04X}", serial >> 16, serial & 0xFFFF)).unwrap_or_default();
    let deleted = walker.entries.iter().filter(|entry| entry.record.deleted).count();
    let description = format!(
        "{} \"{label}\"{serial}, {} clusters, {} entries ({deleted} deleted)",
        geometry.fat_type.label(),
        crate::compress::human_bytes(geometry.cluster_bytes()),
        walker.entries.len()
    );
    let note = (!walker.problems.is_empty()).then(|| walker.problems.join("; "));
    Ok(Filesystem { kind: FsKind::Fat, offset: base, len, description, entries: walker.entries, note })
}

struct Walker<'a> {
    image: &'a [u8],
    base: usize,
    geometry: &'a Geometry,
    fat: &'a [u8],
    entries: Vec<Entry>,
    /// Paths listed so far, to tell a deleted file from a live one of the same name.
    paths: HashSet<String>,
    /// Directory clusters already walked, against loops.
    visited: HashSet<u32>,
    max_entries: usize,
    volume_label: Option<String>,
    problems: Vec<String>,
}

/// One short directory entry with the long name that came before it.
struct DirectoryEntry {
    name: String,
    attributes: u8,
    deleted: bool,
    first_cluster: u32,
    size: usize,
    created: Option<String>,
    modified: Option<String>,
}

impl Walker<'_> {
    /// The root directory's bytes: a fixed region on FAT12 and FAT16, a
    /// cluster chain on FAT32.
    fn root_directory(&mut self) -> Vec<u8> {
        if self.geometry.fat_type == FatType::Fat32 {
            let root = self.geometry.root_cluster;
            self.visited.insert(root);
            return self.chain_bytes(root, usize::MAX).0;
        }
        let end = (self.geometry.root_offset + self.geometry.root_len).min(self.image.len());
        self.image.get(self.geometry.root_offset..end).unwrap_or_default().to_vec()
    }

    /// The table's value for `cluster`.
    fn next_cluster(&self, cluster: u32) -> Option<u32> {
        let index = cluster as usize;
        match self.geometry.fat_type {
            FatType::Fat12 => {
                let pair = le_u16(self.fat, index + index / 2)?;
                Some(u32::from(if index % 2 == 1 { pair >> 4 } else { pair & 0x0FFF }))
            }
            FatType::Fat16 => le_u16(self.fat, index * 2).map(u32::from),
            FatType::Fat32 => le_u32(self.fat, index * 4).map(|value| value & 0x0FFF_FFFF),
        }
    }

    /// Clusters of the chain starting at `first`, at most `limit` of them;
    /// with a problem when the chain breaks off or loops.
    fn chain(&self, first: u32, limit: usize) -> (Vec<u32>, Option<String>) {
        let mut clusters = Vec::new();
        let mut seen = HashSet::new();
        let mut cluster = first;
        while clusters.len() < limit {
            if !self.geometry.is_data_cluster(cluster) {
                return (clusters, Some(format!("the cluster chain reaches invalid cluster {cluster}")));
            }
            if !seen.insert(cluster) {
                return (clusters, Some(format!("the cluster chain loops at cluster {cluster}")));
            }
            clusters.push(cluster);
            match self.next_cluster(cluster) {
                Some(next) if next >= self.geometry.fat_type.end_of_chain() => return (clusters, None),
                Some(0) => return (clusters, Some(format!("the cluster chain runs into free cluster after {cluster}"))),
                Some(next) => cluster = next,
                None => return (clusters, Some("the cluster chain runs off the FAT".to_string())),
            }
        }
        (clusters, None)
    }

    /// The bytes of the chain starting at `first`, at most `limit` of them.
    fn chain_bytes(&self, first: u32, limit: usize) -> (Vec<u8>, Option<String>) {
        let cluster_bytes = self.geometry.cluster_bytes();
        let most_clusters = limit.div_ceil(cluster_bytes).min(self.geometry.clusters as usize);
        let (clusters, problem) = self.chain(first, most_clusters);
        let mut bytes = Vec::new();
        for cluster in clusters {
            let wanted = cluster_bytes.min(limit - bytes.len());
            match slice_at(self.image, self.geometry.cluster_offset(cluster), wanted) {
                Some(data) => bytes.extend_from_slice(data),
                None => return (bytes, Some(format!("cluster {cluster} lies past the end of the volume"))),
            }
        }
        (bytes, problem)
    }

    fn walk_directory(&mut self, listing: &[u8], path: &str, depth: usize, allowance: &mut Allowance) {
        if depth > MAX_DIRECTORY_DEPTH {
            return;
        }
        for entry in parse_directory(listing, self.geometry.fat_type) {
            if self.entries.len() >= self.max_entries {
                self.problems.push(format!("stopped after {} entries", self.max_entries));
                return;
            }
            if entry.attributes & attribute::VOLUME_LABEL != 0 {
                if depth == 0 && !entry.deleted {
                    self.volume_label = Some(entry.name.trim_end_matches('.').to_string());
                }
                continue;
            }
            let mut entry_path = join_path(path, &entry.name);
            if !self.paths.insert(entry_path.clone()) {
                entry_path.push_str(if entry.deleted { " (deleted)" } else { " (again)" });
                self.paths.insert(entry_path.clone());
            }
            if entry.attributes & attribute::DIRECTORY != 0 {
                self.visit_directory(entry, entry_path, depth, allowance);
            } else {
                let file = self.read_file(&entry, entry_path, allowance);
                self.entries.push(file);
            }
        }
    }

    fn visit_directory(&mut self, entry: DirectoryEntry, path: String, depth: usize, allowance: &mut Allowance) {
        let record = EntryRecord { deleted: entry.deleted, created: entry.created.clone(), modified: entry.modified.clone() };
        let mut listed = Entry::directory(path.clone(), self.base + self.geometry.cluster_offset(entry.first_cluster));
        listed.record = record;
        if entry.deleted {
            listed.note = Some("deleted directory: its contents are not listed".to_string());
            self.entries.push(listed);
            return;
        }
        self.entries.push(listed);
        if !self.visited.insert(entry.first_cluster) {
            return;
        }
        let (listing, problem) = self.chain_bytes(entry.first_cluster, usize::MAX);
        if let Some(problem) = problem {
            self.problems.push(format!("{path}: {problem}"));
        }
        self.walk_directory(&listing, &path, depth + 1, allowance);
    }

    fn read_file(&self, entry: &DirectoryEntry, path: String, allowance: &mut Allowance) -> Entry {
        let cap = allowance.cap().unwrap_or(0);
        let wanted = entry.size.min(cap);
        let (content, problem) = if entry.size == 0 {
            (Vec::new(), None)
        } else if entry.deleted {
            self.recover(entry, wanted)
        } else {
            let (bytes, problem) = self.chain_bytes(entry.first_cluster, wanted);
            let short = bytes.len() < wanted;
            (bytes, problem.or_else(|| short.then(|| "the cluster chain is shorter than the file".to_string())))
        };
        let (data, limit_note) = take_content(content, entry.size as u64, allowance);
        let note = match (entry.deleted, problem.or(limit_note)) {
            (true, Some(problem)) => Some(format!("deleted; {problem}")),
            (true, None) => Some(if entry.size == 0 { "deleted".to_string() } else { NOTE_RECOVERED.to_string() }),
            (false, problem) => problem,
        };
        Entry {
            path,
            kind: EntryKind::File,
            declared_size: entry.size as u64,
            data: Arc::new(data),
            // An empty file has no cluster; it is placed at the volume's start.
            source_offset: self.base + if entry.first_cluster == 0 { 0 } else { self.geometry.cluster_offset(entry.first_cluster) },
            source_len: entry.size,
            method: None,
            note,
            record: EntryRecord { deleted: entry.deleted, created: entry.created.clone(), modified: entry.modified.clone() },
        }
    }

    /// A deleted file's bytes, read on from its first cluster as though its
    /// clusters were contiguous; with a problem when some of them now belong
    /// to other files.
    fn recover(&self, entry: &DirectoryEntry, wanted: usize) -> (Vec<u8>, Option<String>) {
        if !self.geometry.is_data_cluster(entry.first_cluster) {
            return (Vec::new(), Some(format!("its first cluster {} is not a data cluster, so nothing was recovered", entry.first_cluster)));
        }
        let start = self.geometry.cluster_offset(entry.first_cluster);
        let end = (start + wanted).min(self.image.len());
        let bytes = self.image.get(start..end).unwrap_or_default().to_vec();
        let clusters = entry.size.div_ceil(self.geometry.cluster_bytes()) as u32;
        let reused = (entry.first_cluster..entry.first_cluster.saturating_add(clusters))
            .filter(|&cluster| self.next_cluster(cluster).is_some_and(|value| value != 0))
            .count();
        let problem = (reused > 0).then(|| format!("recovered, contiguous assumption, but {reused} of its {clusters} clusters are in use by other files"));
        (bytes, problem)
    }
}

/// The short entries of a directory listing with their long names joined,
/// "." and ".." left out. A deleted entry keeps its long name when the
/// long-name parts before it still check against it.
fn parse_directory(listing: &[u8], fat_type: FatType) -> Vec<DirectoryEntry> {
    let mut entries = Vec::new();
    let mut long_parts: Vec<&[u8]> = Vec::new();
    for raw in listing.as_chunks::<DIRECTORY_ENTRY_LEN>().0 {
        if raw[0] == 0 {
            break; // No entries follow.
        }
        if raw[11] == attribute::LONG_NAME {
            long_parts.push(raw);
            continue;
        }
        let parts = std::mem::take(&mut long_parts);
        if raw[..2] == *b". " || raw[..2] == *b".." {
            continue;
        }
        let deleted = raw[0] == DELETED_MARK;
        let mut short = [0u8; 11];
        short.copy_from_slice(&raw[..11]);
        if short[0] == ESCAPED_E5 {
            short[0] = DELETED_MARK;
        }
        let long_name = joined_long_name(&parts, &mut short, deleted);
        let high = if fat_type == FatType::Fat32 { u32::from(le_u16(raw, 20).unwrap_or(0)) << 16 } else { 0 };
        entries.push(DirectoryEntry {
            name: long_name.unwrap_or_else(|| short_name(&short, raw[12], deleted)),
            attributes: raw[11],
            deleted,
            first_cluster: high | u32::from(le_u16(raw, 26).unwrap_or(0)),
            size: le_u32(raw, 28).unwrap_or(0) as usize,
            created: dos_date_time(le_u16(raw, 16).unwrap_or(0), le_u16(raw, 14).unwrap_or(0)),
            modified: dos_date_time(le_u16(raw, 24).unwrap_or(0), le_u16(raw, 22).unwrap_or(0)),
        });
    }
    entries
}

/// The checksum a long-name part carries of its short name.
fn short_name_checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte))
}

/// The long name the parts before a short entry spell, stored last part
/// first, when every part checks against the short name. For a deleted
/// entry, whose short name lost its first byte, the byte that makes the
/// checksum fit is put back into `short`.
fn joined_long_name(parts: &[&[u8]], short: &mut [u8; 11], deleted: bool) -> Option<String> {
    let checksum = parts.first()?[13];
    if parts.iter().any(|part| part[13] != checksum) {
        return None;
    }
    let units: Vec<u16> = parts.iter().rev().flat_map(|part| long_name_units(part)).take_while(|&unit| unit != 0x0000).collect();
    let name = String::from_utf16_lossy(&units);
    if deleted {
        // Try the long name's own first letter, upper-cased, before the rest.
        let guess = name.chars().next().filter(char::is_ascii).map_or(b'_', |first| first.to_ascii_uppercase() as u8);
        let first = std::iter::once(guess).chain(0x20..=0xFF).find(|&byte| {
            short[0] = byte;
            short_name_checksum(short) == checksum
        })?;
        short[0] = first;
    } else if short_name_checksum(short) != checksum {
        return None;
    }
    (!name.is_empty()).then_some(name.replace('/', "_"))
}

/// The 13 UTF-16 units one long-name part holds, at 1, 14 and 28.
fn long_name_units(part: &[u8]) -> impl Iterator<Item = u16> + '_ {
    [(1usize, 5usize), (14, 6), (28, 2)]
        .into_iter()
        .flat_map(move |(at, count)| (0..count).map(move |index| le_u16(part, at + index * 2).unwrap_or(0)))
        .filter(|&unit| unit != 0xFFFF)
}

/// "NAME.EXT" from an 8.3 entry, lower-cased where the case byte says, with
/// the lost first character of a deleted name shown as `LOST_CHARACTER`.
fn short_name(short: &[u8; 11], case: u8, deleted: bool) -> String {
    let text = |bytes: &[u8], lower: bool| {
        let part: String = bytes.iter().map(|&byte| byte as char).collect::<String>().trim_end().to_string();
        if lower { part.to_ascii_lowercase() } else { part }
    };
    let mut base = text(&short[..8], case & 0x08 != 0);
    if deleted {
        base.replace_range(..base.chars().next().map_or(0, char::len_utf8), &LOST_CHARACTER.to_string());
    }
    let extension = text(&short[8..], case & 0x10 != 0);
    let name = if extension.is_empty() { base } else { format!("{base}.{extension}") };
    name.replace('/', "_")
}

/// A DOS date and time as "2026-09-12 08:14:54", a local wall-clock time
/// with no zone. `None` for an unset or impossible date.
pub fn dos_date_time(date: u16, time: u16) -> Option<String> {
    let (year, month, day) = (1980 + (date >> 9), (date >> 5) & 0x0F, date & 0x1F);
    let (hour, minute, second) = (time >> 11, (time >> 5) & 0x3F, (time & 0x1F) * 2);
    if date == 0 || !(1..=12).contains(&month) || day == 0 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::unpack::Limits;

    const SECTOR: usize = 512;

    /// A file or directory to place in a test volume.
    pub struct Item<'a> {
        pub short: &'a [u8; 11],
        pub long: Option<&'a str>,
        pub content: &'a [u8],
        pub deleted: bool,
        pub children: Vec<Item<'a>>,
    }

    impl<'a> Item<'a> {
        pub fn file(short: &'a [u8; 11], long: Option<&'a str>, content: &'a [u8]) -> Self {
            Item { short, long, content, deleted: false, children: Vec::new() }
        }

        pub fn deleted(mut self) -> Self {
            self.deleted = true;
            self
        }

        fn directory(short: &'a [u8; 11], children: Vec<Item<'a>>) -> Self {
            Item { short, long: None, content: b"", deleted: false, children }
        }
    }

    /// 2026-09-12 08:14:54 as a DOS date and time.
    const DATE: u16 = (46 << 9) | (9 << 5) | 12;
    const TIME: u16 = (8 << 11) | (14 << 5) | 27;

    fn long_entries(long: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
        let mut units: Vec<u16> = long.encode_utf16().collect();
        units.push(0);
        while !units.len().is_multiple_of(13) {
            units.push(0xFFFF);
        }
        let checksum = short_name_checksum(short);
        let parts = units.len() / 13;
        (0..parts)
            .rev()
            .map(|index| {
                let mut entry = [0u8; 32];
                entry[0] = (index + 1) as u8 | if index + 1 == parts { 0x40 } else { 0 };
                entry[11] = attribute::LONG_NAME;
                entry[13] = checksum;
                let chunk = &units[index * 13..index * 13 + 13];
                for (slot, &unit) in chunk.iter().enumerate() {
                    let at = match slot {
                        0..=4 => 1 + slot * 2,
                        5..=10 => 14 + (slot - 5) * 2,
                        _ => 28 + (slot - 11) * 2,
                    };
                    entry[at..at + 2].copy_from_slice(&unit.to_le_bytes());
                }
                entry
            })
            .collect()
    }

    fn short_entry(short: &[u8; 11], attributes: u8, cluster: u16, size: u32) -> [u8; 32] {
        let mut entry = [0u8; 32];
        entry[..11].copy_from_slice(short);
        entry[11] = attributes;
        entry[14..16].copy_from_slice(&TIME.to_le_bytes());
        entry[16..18].copy_from_slice(&DATE.to_le_bytes());
        entry[22..24].copy_from_slice(&TIME.to_le_bytes());
        entry[24..26].copy_from_slice(&DATE.to_le_bytes());
        entry[26..28].copy_from_slice(&cluster.to_le_bytes());
        entry[28..32].copy_from_slice(&size.to_le_bytes());
        entry
    }

    struct Builder {
        volume: Vec<u8>,
        geometry: Geometry,
        next_cluster: u32,
    }

    impl Builder {
        fn set_fat(&mut self, cluster: u32, value: u32) {
            for copy in 0..self.geometry.fat_count {
                let fat = self.geometry.fat_offset + copy * self.geometry.fat_len();
                let index = cluster as usize;
                match self.geometry.fat_type {
                    FatType::Fat12 => {
                        let at = fat + index + index / 2;
                        let pair = u16::from_le_bytes([self.volume[at], self.volume[at + 1]]);
                        let pair = if index % 2 == 1 { (pair & 0x000F) | ((value as u16) << 4) } else { (pair & 0xF000) | (value as u16 & 0x0FFF) };
                        self.volume[at..at + 2].copy_from_slice(&pair.to_le_bytes());
                    }
                    FatType::Fat16 => self.volume[fat + index * 2..fat + index * 2 + 2].copy_from_slice(&(value as u16).to_le_bytes()),
                    FatType::Fat32 => self.volume[fat + index * 4..fat + index * 4 + 4].copy_from_slice(&value.to_le_bytes()),
                }
            }
        }

        /// Store `content` in fresh clusters, chained unless `free`; returns the first.
        fn store(&mut self, content: &[u8], free: bool) -> u32 {
            let count = content.len().div_ceil(self.geometry.cluster_bytes()).max(1) as u32;
            let first = self.next_cluster;
            self.next_cluster += count;
            for cluster in first..first + count {
                let next = if cluster + 1 == first + count { self.geometry.fat_type.end_of_chain() | 0xF } else { cluster + 1 };
                if !free {
                    self.set_fat(cluster, next & 0x0FFF_FFFF);
                }
            }
            let at = self.geometry.cluster_offset(first);
            self.volume[at..at + content.len()].copy_from_slice(content);
            first
        }

        fn listing(&mut self, items: &[Item]) -> Vec<u8> {
            let mut listing = Vec::new();
            for item in items {
                let is_directory = !item.children.is_empty();
                let (cluster, size) = if is_directory {
                    let children = self.listing(&item.children);
                    (self.store(&children, false), 0)
                } else if item.content.is_empty() {
                    (0, 0)
                } else {
                    (self.store(item.content, item.deleted), item.content.len() as u32)
                };
                let mut entries = item.long.map(|long| long_entries(long, item.short)).unwrap_or_default();
                let attributes = if is_directory { attribute::DIRECTORY } else { 0x20 };
                entries.push(short_entry(item.short, attributes, cluster as u16, size));
                if item.deleted {
                    for entry in &mut entries {
                        entry[0] = DELETED_MARK;
                    }
                }
                listing.extend(entries.iter().flatten());
            }
            listing
        }
    }

    /// A FAT12 or FAT16 volume (by `total_sectors`) holding `items`, with
    /// a volume label.
    pub fn build_volume(total_sectors: usize, sectors_per_cluster: u8, items: &[Item]) -> Vec<u8> {
        let mut boot = vec![0u8; SECTOR];
        boot[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        boot[3..11].copy_from_slice(b"MSWIN4.1");
        boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        boot[13] = sectors_per_cluster;
        boot[14..16].copy_from_slice(&4u16.to_le_bytes());
        boot[16] = 2;
        boot[17..19].copy_from_slice(&512u16.to_le_bytes());
        boot[19..21].copy_from_slice(&(total_sectors as u16).to_le_bytes());
        boot[21] = 0xF8;
        let clusters_guess = total_sectors / sectors_per_cluster as usize;
        let sectors_per_fat = (clusters_guess * 2).div_ceil(SECTOR) as u16;
        boot[22..24].copy_from_slice(&sectors_per_fat.to_le_bytes());
        boot[28..32].copy_from_slice(&2048u32.to_le_bytes());
        boot[38] = 0x29;
        boot[39..43].copy_from_slice(&0x1234_ABCDu32.to_le_bytes());
        boot[43..54].copy_from_slice(b"NO NAME    ");
        boot[54..62].copy_from_slice(b"FAT16   "); // Only a label: the cluster count decides.
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        let geometry = geometry(&boot).unwrap();
        let mut builder = Builder { volume: vec![0u8; total_sectors * SECTOR], geometry, next_cluster: 2 };
        builder.volume[..SECTOR].copy_from_slice(&boot);
        let media = match builder.geometry.fat_type {
            FatType::Fat12 => 0xFF8,
            FatType::Fat16 => 0xFFF8,
            FatType::Fat32 => 0x0FFF_FFF8,
        };
        builder.set_fat(0, media);
        builder.set_fat(1, media | 0x7);
        let mut root = short_entry(b"KINGSTON   ", attribute::VOLUME_LABEL, 0, 0).to_vec();
        root.extend(builder.listing(items));
        let at = builder.geometry.root_offset;
        builder.volume[at..at + root.len()].copy_from_slice(&root);
        builder.volume
    }

    fn sample(total_sectors: usize) -> (Vec<u8>, Vec<u8>) {
        let photo: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 251) as u8).collect();
        let volume = build_volume(total_sectors, 2, &[
            Item::file(b"NOTES   TXT", None, b"zip it, pw on the yellow note\n"),
            Item::file(b"IMG_20~1JPG", Some("IMG_20260912_0814.jpg"), &photo).deleted(),
            Item::file(b"BACKUP~1ZIP", Some("backup_0912.zip"), &[0x50; 3000]),
            Item::directory(b"SYSTEM~1   ", vec![Item::file(b"INDEXE~1   ", Some("IndexerVolumeGuid"), b"{guid}")]),
            Item::file(b"OLDNOTE TXT", None, b"gone").deleted(),
        ]);
        (volume, photo)
    }

    fn read_volume(volume: &[u8]) -> Filesystem {
        let mut left = usize::MAX;
        read(volume, 0, &mut Allowance::new(&Limits::default(), &mut left)).unwrap()
    }

    #[test]
    fn live_and_deleted_files_are_listed_with_long_names_and_times() {
        let (volume, photo) = sample(16384);
        let filesystem = read_volume(&volume);
        assert!(filesystem.note.is_none(), "{:?}", filesystem.note);
        let paths: Vec<&str> = filesystem.entries.iter().map(|entry| entry.path.as_str()).collect();
        assert_eq!(paths, ["NOTES.TXT", "IMG_20260912_0814.jpg", "backup_0912.zip", "SYSTEM~1", "SYSTEM~1/IndexerVolumeGuid", "_LDNOTE.TXT"]);
        let find = |path: &str| filesystem.entries.iter().find(|entry| entry.path == path).unwrap();
        let deleted = find("IMG_20260912_0814.jpg");
        assert!(deleted.record.deleted);
        assert_eq!(deleted.note.as_deref(), Some(NOTE_RECOVERED));
        assert_eq!(deleted.data.as_slice(), photo.as_slice(), "recovered from its freed clusters");
        assert_eq!(deleted.record.modified.as_deref(), Some("2026-09-12 08:14:54"));
        assert_eq!(find("NOTES.TXT").data.as_slice(), b"zip it, pw on the yellow note\n");
        assert!(!find("NOTES.TXT").record.deleted);
        assert_eq!(find("backup_0912.zip").data.len(), 3000, "a chain of several clusters");
        assert_eq!(find("SYSTEM~1/IndexerVolumeGuid").data.as_slice(), b"{guid}");
        assert!(find("_LDNOTE.TXT").record.deleted, "a deleted name without a long name loses its first letter");
        assert!(filesystem.description.starts_with("FAT16 \"KINGSTON\", serial 1234-ABCD"), "{}", filesystem.description);
    }

    #[test]
    fn the_type_follows_the_cluster_count_not_the_label_in_the_boot_sector() {
        let (small, _) = sample(4096);
        assert_eq!(geometry(&small).unwrap().fat_type, FatType::Fat12, "about 2000 clusters, though labelled FAT16");
        let filesystem = read_volume(&small);
        assert!(filesystem.description.starts_with("FAT12"), "{}", filesystem.description);
        assert_eq!(filesystem.file_count(), 5);
        let (large, _) = sample(16384);
        let geometry = geometry(&large).unwrap();
        assert_eq!(geometry.fat_type, FatType::Fat16);
        assert_eq!((geometry.sectors_per_fat, geometry.hidden_sectors, geometry.serial), (32, 2048, Some(0x1234_ABCD)));
        assert_eq!((geometry.fat_offset, geometry.root_offset, geometry.data_offset), (2048, 2048 + 2 * 32 * 512, 2048 + 2 * 32 * 512 + 512 * 32));
    }

    #[test]
    fn a_deleted_file_whose_clusters_were_reused_says_so() {
        let (mut volume, _) = sample(16384);
        let geometry = geometry(&volume).unwrap();
        // Cluster 3 holds the start of the deleted photo; claim it for another file.
        let at = geometry.fat_offset + 3 * 2;
        volume[at..at + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let filesystem = read_volume(&volume);
        let photo = filesystem.entries.iter().find(|entry| entry.path == "IMG_20260912_0814.jpg").unwrap();
        assert!(photo.note.as_deref().unwrap().contains("1 of its 5 clusters are in use"), "{:?}", photo.note);
    }

    #[test]
    fn dos_times_decode_and_impossible_ones_are_refused() {
        assert_eq!(dos_date_time(DATE, TIME).as_deref(), Some("2026-09-12 08:14:54"));
        assert_eq!(dos_date_time(0, 0), None);
        assert_eq!(dos_date_time((46 << 9) | (13 << 5) | 1, 0), None, "month 13");
    }

    #[test]
    fn other_boot_sectors_and_damaged_volumes_do_not_panic() {
        let (volume, _) = sample(4096);
        let mut ntfs = volume[..SECTOR].to_vec();
        ntfs[14..17].fill(0);
        assert!(geometry(&ntfs).is_err());
        for cut in [10, 511, 600, 5000, volume.len() / 2] {
            let mut left = usize::MAX;
            let _ = read(&volume[..cut], 0, &mut Allowance::new(&Limits::default(), &mut left));
        }
        let noise = super::super::test_support::noise(volume.len(), 9);
        for step in [3, 7, 31] {
            let mut damaged = volume.clone();
            for index in (SECTOR..damaged.len()).step_by(step) {
                damaged[index] ^= noise[index];
            }
            let mut left = 1 << 20;
            let _ = read(&damaged, 0, &mut Allowance::new(&Limits::default(), &mut left));
        }
    }
}
