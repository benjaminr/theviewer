//! Disk and filesystem structures: MBR partition tables (via mbrman), GPT
//! headers and entries, FAT and NTFS boot sectors, and ext2/3/4 superblocks.

use std::io::Cursor;

use super::{MAX_CHILDREN, fixed_string, guarded, u16le, u32le, u64le};
use crate::embedfs::fat::{self, FatType, Geometry};
use crate::plugin::{Category, Field, Finding, Parser};

const SOURCE: &str = "parsers.disk";
const SECTOR: usize = 512;

// ---------------------------------------------------------------------------
// MBR
// ---------------------------------------------------------------------------

pub struct MbrParser;

fn partition_type_name(sys: u8) -> &'static str {
    match sys {
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x05 | 0x0F => "extended",
        0x07 => "NTFS/exFAT",
        0x0B | 0x0C => "FAT32",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8E => "Linux LVM",
        0xA5 => "FreeBSD",
        0xAF => "HFS+",
        0xEE => "GPT protective",
        0xEF => "EFI system",
        _ => "other",
    }
}

/// A sector with the 55 AA signature, valid status bytes, and at least one
/// used partition. Boot sectors with an empty table are left to the
/// filesystem parsers.
fn looks_like_mbr(bytes: &[u8]) -> bool {
    if bytes.len() < SECTOR || bytes[510] != 0x55 || bytes[511] != 0xAA {
        return false;
    }
    let mut used = 0;
    for index in 0..4 {
        let entry = &bytes[446 + index * 16..446 + (index + 1) * 16];
        if !matches!(entry[0], 0x00 | 0x80) {
            return false;
        }
        let sys = entry[4];
        let sectors = u32le(entry, 12).unwrap_or(0);
        if sys != 0 && sectors > 0 {
            used += 1;
        }
    }
    used > 0
}

impl Parser for MbrParser {
    fn id(&self) -> &str {
        "mbr"
    }

    fn name(&self) -> &str {
        "MBR partition table"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        looks_like_mbr(bytes)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !looks_like_mbr(bytes) {
            return None;
        }
        let mbr = guarded(|| mbrman::MBR::read_from(&mut Cursor::new(&bytes[..SECTOR]), SECTOR as u32).ok())?;
        let mut partitions = Vec::new();
        let mut summary = Vec::new();
        for (index, entry) in mbr.iter() {
            if !entry.is_used() {
                continue;
            }
            let at = 446 + (index - 1) * 16;
            let kind = partition_type_name(entry.sys);
            let active = if entry.boot == 0x80 { ", active" } else { "" };
            partitions.push(
                Field::new(
                    format!("partition {index}"),
                    base + at,
                    16,
                    format!("{kind} ({:#04x}), LBA {} + {} sectors{active}", entry.sys, entry.starting_lba, entry.sectors),
                )
                .with_children(vec![
                    Field::new("status", base + at, 1, format!("{:#04x}", entry.boot)),
                    Field::new("type", base + at + 4, 1, kind),
                    Field::new("starting LBA", base + at + 8, 4, entry.starting_lba.to_string()),
                    Field::new("sectors", base + at + 12, 4, entry.sectors.to_string()),
                ]),
            );
            summary.push(kind.to_string());
        }
        if partitions.is_empty() {
            return None;
        }
        let count = partitions.len();
        Some(
            Finding::new("mbr", SOURCE, Category::Filesystem, base, SECTOR)
                .title("MBR partition table")
                .detail(format!("MBR with {count} partitions: {}", summary.join(", ")))
                .fields(vec![
                    Field::new("boot code", base, 446, "x86 boot code"),
                    Field::new("partition table", base + 446, 64, format!("{count} used entries")).with_children(partitions),
                    Field::new("signature", base + 510, 2, "55 AA"),
                ]),
        )
    }
}

// ---------------------------------------------------------------------------
// GPT
// ---------------------------------------------------------------------------

pub struct GptParser;

const GPT_SIGNATURE: &[u8] = b"EFI PART";

/// Mixed-endian GUID text as Windows and UEFI print it.
fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32le(bytes, 0).unwrap_or(0),
        u16le(bytes, 4).unwrap_or(0),
        u16le(bytes, 6).unwrap_or(0),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn gpt_type_name(guid: &str) -> &'static str {
    match guid {
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System",
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft basic data",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft reserved",
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows recovery",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux filesystem",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux swap",
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => "Linux LVM",
        "21686148-6449-6E6F-744E-656564454649" => "BIOS boot",
        "7C3457EF-0000-11AA-AA11-00306543ECAC" => "Apple APFS",
        "48465300-0000-11AA-AA11-00306543ECAC" => "Apple HFS+",
        "426F6F74-0000-11AA-AA11-00306543ECAC" => "Apple boot",
        _ => "other",
    }
}

fn utf16le_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    String::from_utf16_lossy(&units)
}

impl Parser for GptParser {
    fn id(&self) -> &str {
        "gpt"
    }

    fn name(&self) -> &str {
        "GPT partition table"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(GPT_SIGNATURE) && bytes.len() >= 92
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let revision = u32le(bytes, 8)?;
        let header_size = u32le(bytes, 12)?;
        let current_lba = u64le(bytes, 24)?;
        let backup_lba = u64le(bytes, 32)?;
        let first_usable = u64le(bytes, 40)?;
        let last_usable = u64le(bytes, 48)?;
        let disk_guid = format_guid(&bytes[56..72]);
        let entries_lba = u64le(bytes, 72)?;
        let entry_count = u32le(bytes, 80)? as usize;
        let entry_size = u32le(bytes, 84)? as usize;
        if !(92..=4096).contains(&(header_size as usize)) || !(32..=4096).contains(&entry_size) || entry_count > 1024 {
            return None;
        }
        let mut fields = vec![
            Field::new("GPT header", base, header_size as usize, format!("revision {:#x}", revision)).with_children(vec![
                Field::new("header size", base + 12, 4, header_size.to_string()),
                Field::new("current LBA", base + 24, 8, current_lba.to_string()),
                Field::new("backup LBA", base + 32, 8, backup_lba.to_string()),
                Field::new("first usable LBA", base + 40, 8, first_usable.to_string()),
                Field::new("last usable LBA", base + 48, 8, last_usable.to_string()),
                Field::new("disk GUID", base + 56, 16, disk_guid.clone()),
                Field::new("entries LBA", base + 72, 8, entries_lba.to_string()),
                Field::new("entry count", base + 80, 4, entry_count.to_string()),
                Field::new("entry size", base + 84, 4, entry_size.to_string()),
            ]),
        ];
        let mut extent = header_size as usize;
        let mut names = Vec::new();
        if entries_lba > current_lba {
            let entries_at = ((entries_lba - current_lba) as usize).saturating_mul(SECTOR);
            if entries_at < bytes.len() {
                let mut entries = Vec::new();
                for index in 0..entry_count.min(MAX_CHILDREN) {
                    let at = entries_at + index * entry_size;
                    let Some(entry) = bytes.get(at..at + entry_size.min(128)) else { break };
                    if entry[..16].iter().all(|&b| b == 0) {
                        continue;
                    }
                    let type_guid = format_guid(&entry[..16]);
                    let unique = format_guid(&entry[16..32]);
                    let first = u64le(entry, 32).unwrap_or(0);
                    let last = u64le(entry, 40).unwrap_or(0);
                    let name = if entry.len() >= 128 { utf16le_string(&entry[56..128]) } else { String::new() };
                    let kind = gpt_type_name(&type_guid);
                    names.push(if name.is_empty() { kind.to_string() } else { format!("{name} ({kind})") });
                    entries.push(
                        Field::new(format!("entry {}", index + 1), base + at, entry_size, format!("{kind}, LBA {first}..{last}, \"{name}\"")).with_children(vec![
                            Field::new("type GUID", base + at, 16, format!("{type_guid} ({kind})")),
                            Field::new("unique GUID", base + at + 16, 16, unique),
                            Field::new("first LBA", base + at + 32, 8, first.to_string()),
                            Field::new("last LBA", base + at + 40, 8, last.to_string()),
                            Field::new("name", base + at + 56, 72, name),
                        ]),
                    );
                    extent = extent.max(at + entry_size);
                }
                let count = entries.len();
                fields.push(Field::new("partition entries", base + entries_at, entry_count * entry_size, format!("{count} used entries")).with_children(entries));
                extent = extent.max(entries_at + entry_count * entry_size);
            }
        }
        let extent = extent.min(bytes.len());
        Some(
            Finding::new("gpt", SOURCE, Category::Filesystem, base, extent)
                .title("GPT partition table")
                .detail(format!("GPT disk {disk_guid}, {entry_count} entry slots: {}", if names.is_empty() { "entries not in view".to_string() } else { names.join(", ") }))
                .fields(fields),
        )
    }
}

// ---------------------------------------------------------------------------
// FAT and NTFS boot sectors
// ---------------------------------------------------------------------------

pub struct FatParser;

fn has_boot_jump(bytes: &[u8]) -> bool {
    (bytes[0] == 0xEB && bytes[2] == 0x90) || bytes[0] == 0xE9
}

/// The informational type string at 54 (FAT12/16) or 82 (FAT32), and where.
fn fat_type_string(bytes: &[u8]) -> Option<(&'static str, usize)> {
    if bytes.get(54..59) == Some(b"FAT12") {
        Some(("FAT12", 54))
    } else if bytes.get(54..59) == Some(b"FAT16") {
        Some(("FAT16", 54))
    } else if bytes.get(54..57) == Some(b"FAT") {
        Some(("FAT", 54))
    } else if bytes.get(82..87) == Some(b"FAT32") {
        Some(("FAT32", 82))
    } else {
        None
    }
}

/// "0x100400 (volume + 0x400)": where a region is in the document and in
/// the volume.
fn volume_offset(base: usize, offset: usize) -> String {
    format!("{:#x} (volume + {offset:#x})", base + offset)
}

/// Fields worked out from the BIOS parameter block: the FAT type by cluster
/// count, and where the tables, root directory and data area start. Each
/// is placed on the field it is chiefly computed from.
fn derived_fat_fields(geometry: &Geometry, base: usize) -> Vec<Field> {
    let mut fields = vec![
        Field::new("FAT type (by cluster count)", base + if geometry.total_sectors > 0xFFFF { 32 } else { 19 }, if geometry.total_sectors > 0xFFFF { 4 } else { 2 }, format!("{}, {} clusters of {} bytes", geometry.fat_type.label(), geometry.clusters, geometry.cluster_bytes())),
        Field::new("first FAT at", base + 14, 2, volume_offset(base, geometry.fat_offset)),
    ];
    if geometry.fat_type == FatType::Fat32 {
        fields.push(Field::new("root directory at", base + 44, 4, format!("cluster {}, {}", geometry.root_cluster, volume_offset(base, geometry.cluster_offset(geometry.root_cluster)))));
    } else {
        fields.push(Field::new("root directory at", base + 17, 2, format!("{}, {} bytes", volume_offset(base, geometry.root_offset), geometry.root_len)));
    }
    fields.push(Field::new("data area at", base + 13, 1, format!("{} (cluster 2)", volume_offset(base, geometry.data_offset))));
    fields
}

impl Parser for FatParser {
    fn id(&self) -> &str {
        "fat"
    }

    fn name(&self) -> &str {
        "FAT boot sector"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.len() >= SECTOR
            && has_boot_jump(bytes)
            && bytes[510] == 0x55
            && bytes[511] == 0xAA
            && u16le(bytes, 11).is_some_and(|bps| matches!(bps, 512 | 1024 | 2048 | 4096))
            && bytes[13].is_power_of_two()
            && (fat_type_string(bytes).is_some() || fat::geometry(bytes).is_ok())
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let type_string = fat_type_string(bytes);
        let geometry = fat::geometry(bytes);
        // The cluster count decides the type; the string is only a label.
        let kind = match (&geometry, type_string) {
            (Ok(geometry), _) => geometry.fat_type.label(),
            (Err(_), Some((label, _))) => label,
            (Err(_), None) => "FAT",
        };
        let is_fat32 = kind == "FAT32" || type_string.is_some_and(|(label, _)| label == "FAT32");
        let bytes_per_sector = u16le(bytes, 11)?;
        let sectors_per_cluster = bytes[13];
        let reserved = u16le(bytes, 14)?;
        let fats = bytes[16];
        let root_entries = u16le(bytes, 17)?;
        let total_16 = u16le(bytes, 19)?;
        let total_32 = u32le(bytes, 32)?;
        let total = if total_16 != 0 { total_16 as u32 } else { total_32 };
        let fat_16 = u16le(bytes, 22)?;
        let (sectors_per_fat, sectors_per_fat_at, sectors_per_fat_len) = if fat_16 != 0 { (u32::from(fat_16), 22, 2) } else { (u32le(bytes, 36)?, 36, 4) };
        let oem = fixed_string(&bytes[3..11]);
        let label_at = if is_fat32 { 71 } else { 43 };
        let label = fixed_string(&bytes[label_at..label_at + 11]);
        let size = total as u64 * bytes_per_sector as u64;
        let mut fields = vec![
            Field::new("jump", base, 3, super::hex_preview(&bytes[..3], 3)),
            Field::new("OEM name", base + 3, 8, oem),
            Field::new("bytes per sector", base + 11, 2, bytes_per_sector.to_string()),
            Field::new("sectors per cluster", base + 13, 1, sectors_per_cluster.to_string()),
            Field::new("reserved sectors", base + 14, 2, reserved.to_string()),
            Field::new("FAT count", base + 16, 1, fats.to_string()),
            Field::new("root entries", base + 17, 2, root_entries.to_string()),
            Field::new("total sectors", base + if total_16 != 0 { 19 } else { 32 }, if total_16 != 0 { 2 } else { 4 }, total.to_string()),
            Field::new("media", base + 21, 1, format!("{:#04x}", bytes[21])),
            Field::new("sectors per FAT", base + sectors_per_fat_at, sectors_per_fat_len, sectors_per_fat.to_string()),
            Field::new("hidden sectors", base + 28, 4, u32le(bytes, 28)?.to_string()),
        ];
        let mut detail = format!(
            "{kind}, {bytes_per_sector} per sector, {sectors_per_cluster} sectors per cluster, {fats} FATs of {sectors_per_fat} sectors, {total} sectors ({}), label \"{label}\"",
            super::human_bytes(size)
        );
        match &geometry {
            Ok(geometry) => {
                if let Some(serial) = geometry.serial {
                    fields.push(Field::new("volume serial", base + geometry.serial_at, 4, format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF)));
                }
                fields.extend(derived_fat_fields(geometry, base));
                detail.push_str(&format!(", data at volume + {:#x}", geometry.data_offset));
            }
            Err(problem) => detail.push_str(&format!("; the layout does not add up: {problem}")),
        }
        fields.push(Field::new("volume label", base + label_at, 11, label));
        if let Some((label, type_at)) = type_string {
            fields.push(Field::new("filesystem type (label)", base + type_at, 8, label));
        }
        fields.push(Field::new("signature", base + 510, 2, "55 AA"));
        Some(
            Finding::new("fat", SOURCE, Category::Filesystem, base, SECTOR)
                .title(format!("{kind} boot sector"))
                .detail(detail)
                .confidence(if geometry.is_ok() { 1.0 } else { 0.6 })
                .fields(fields),
        )
    }
}

pub struct NtfsParser;

impl Parser for NtfsParser {
    fn id(&self) -> &str {
        "ntfs"
    }

    fn name(&self) -> &str {
        "NTFS boot sector"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.len() >= SECTOR && bytes.get(3..11) == Some(b"NTFS    ") && bytes[510] == 0x55 && bytes[511] == 0xAA
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let bytes_per_sector = u16le(bytes, 11)?;
        let sectors_per_cluster = bytes[13];
        let total_sectors = u64le(bytes, 40)?;
        let mft_cluster = u64le(bytes, 48)?;
        let mft_mirror = u64le(bytes, 56)?;
        let serial = u64le(bytes, 72)?;
        let size = total_sectors * bytes_per_sector as u64;
        Some(
            Finding::new("ntfs", SOURCE, Category::Filesystem, base, SECTOR)
                .title("NTFS boot sector")
                .detail(format!("NTFS, {total_sectors} sectors ({}), MFT at cluster {mft_cluster}", super::human_bytes(size)))
                .fields(vec![
                    Field::new("OEM ID", base + 3, 8, "NTFS"),
                    Field::new("bytes per sector", base + 11, 2, bytes_per_sector.to_string()),
                    Field::new("sectors per cluster", base + 13, 1, sectors_per_cluster.to_string()),
                    Field::new("total sectors", base + 40, 8, total_sectors.to_string()),
                    Field::new("MFT cluster", base + 48, 8, mft_cluster.to_string()),
                    Field::new("MFT mirror cluster", base + 56, 8, mft_mirror.to_string()),
                    Field::new("volume serial", base + 72, 8, format!("{serial:#018x}")),
                    Field::new("signature", base + 510, 2, "55 AA"),
                ]),
        )
    }
}

// ---------------------------------------------------------------------------
// ext2/3/4 superblock
// ---------------------------------------------------------------------------

pub struct ExtParser;

const EXT_SUPERBLOCK_AT: usize = 1024;
const EXT_MAGIC: u16 = 0xEF53;
const EXT_SUPERBLOCK_LEN: usize = 264;

impl Parser for ExtParser {
    fn id(&self) -> &str {
        "ext"
    }

    fn name(&self) -> &str {
        "ext2/3/4 superblock"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.len() >= EXT_SUPERBLOCK_AT + EXT_SUPERBLOCK_LEN && u16le(bytes, EXT_SUPERBLOCK_AT + 56) == Some(EXT_MAGIC)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let sb = EXT_SUPERBLOCK_AT;
        let inodes = u32le(bytes, sb)?;
        let blocks = u32le(bytes, sb + 4)?;
        let log_block_size = u32le(bytes, sb + 24)?;
        if log_block_size > 6 {
            return None;
        }
        let block_size = 1024u64 << log_block_size;
        let blocks_per_group = u32le(bytes, sb + 32)?;
        let state = u16le(bytes, sb + 58)?;
        let revision = u32le(bytes, sb + 76)?;
        let feature_compat = u32le(bytes, sb + 92)?;
        let feature_incompat = u32le(bytes, sb + 96)?;
        let volume_name = fixed_string(&bytes[sb + 120..sb + 136]);
        let last_mounted = fixed_string(&bytes[sb + 136..sb + 200]);
        let kind = if feature_incompat & 0x40 != 0 || feature_incompat & 0x200 != 0 {
            "ext4"
        } else if feature_compat & 0x4 != 0 {
            "ext3"
        } else {
            "ext2"
        };
        let size = blocks as u64 * block_size;
        Some(
            Finding::new("ext", SOURCE, Category::Filesystem, base + sb, EXT_SUPERBLOCK_LEN)
                .title(format!("{kind} superblock"))
                .detail(format!("{kind}, {blocks} blocks of {block_size} ({}), {inodes} inodes, label \"{volume_name}\"", super::human_bytes(size)))
                .fields(vec![
                    Field::new("inodes count", base + sb, 4, inodes.to_string()),
                    Field::new("blocks count", base + sb + 4, 4, blocks.to_string()),
                    Field::new("block size", base + sb + 24, 4, block_size.to_string()),
                    Field::new("blocks per group", base + sb + 32, 4, blocks_per_group.to_string()),
                    Field::new("magic", base + sb + 56, 2, "EF53"),
                    Field::new("state", base + sb + 58, 2, if state & 1 != 0 { "clean" } else { "errors or mounted" }),
                    Field::new("revision", base + sb + 76, 4, revision.to_string()),
                    Field::new("feature_compat", base + sb + 92, 4, format!("{feature_compat:#x}")),
                    Field::new("feature_incompat", base + sb + 96, 4, format!("{feature_incompat:#x}")),
                    Field::new("volume name", base + sb + 120, 16, volume_name),
                    Field::new("last mounted", base + sb + 136, 64, last_mounted),
                ]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mbr_with_two_partitions() -> Vec<u8> {
        let mut sector = vec![0u8; SECTOR];
        sector[510] = 0x55;
        sector[511] = 0xAA;
        let entry = |at: usize, boot: u8, sys: u8, lba: u32, sectors: u32, sector: &mut Vec<u8>| {
            sector[at] = boot;
            sector[at + 4] = sys;
            sector[at + 8..at + 12].copy_from_slice(&lba.to_le_bytes());
            sector[at + 12..at + 16].copy_from_slice(&sectors.to_le_bytes());
        };
        entry(446, 0x80, 0x0C, 2048, 204_800, &mut sector);
        entry(462, 0x00, 0x83, 206_848, 1_000_000, &mut sector);
        sector
    }

    #[test]
    fn mbr_partitions_are_listed_and_empty_tables_are_ignored() {
        let bytes = mbr_with_two_partitions();
        assert!(MbrParser.looks_like(&bytes));
        let finding = MbrParser.parse(&bytes, 0).expect("mbr");
        assert!(finding.detail.contains("FAT32, Linux"), "{}", finding.detail);
        let table = &finding.fields[1];
        assert_eq!(table.children.len(), 2);
        assert_eq!(table.children[1].offset, 462);
        let mut empty = vec![0u8; SECTOR];
        empty[510] = 0x55;
        empty[511] = 0xAA;
        assert!(!MbrParser.looks_like(&empty));
    }

    #[test]
    fn gpt_header_and_entries_are_parsed() {
        let mut bytes = vec![0u8; 1024];
        bytes[..8].copy_from_slice(GPT_SIGNATURE);
        bytes[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&92u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&1u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&1000u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&34u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&966u64.to_le_bytes());
        bytes[72..80].copy_from_slice(&2u64.to_le_bytes());
        bytes[80..84].copy_from_slice(&4u32.to_le_bytes());
        bytes[84..88].copy_from_slice(&128u32.to_le_bytes());
        // One entry at LBA 2 (offset 512): EFI System.
        let efi = [0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B];
        bytes[512..528].copy_from_slice(&efi);
        bytes[544..552].copy_from_slice(&34u64.to_le_bytes());
        bytes[552..560].copy_from_slice(&500u64.to_le_bytes());
        for (i, unit) in "EFI".encode_utf16().enumerate() {
            bytes[568 + i * 2..570 + i * 2].copy_from_slice(&unit.to_le_bytes());
        }
        let finding = GptParser.parse(&bytes, 512).expect("gpt");
        assert!(finding.detail.contains("EFI (EFI System)"), "{}", finding.detail);
        let entries = finding.fields.iter().find(|f| f.name == "partition entries").expect("entries");
        assert_eq!(entries.children.len(), 1);
        assert_eq!(entries.children[0].offset, 1024);
    }

    #[test]
    fn a_fat_boot_sector_gives_the_geometry_every_later_offset_depends_on() {
        let (disk, _) = crate::embedfs::test_support::fat_disk();
        let base = 63 * SECTOR;
        let finding = FatParser.parse(&disk[base..], base).expect("fat");
        let field = |name: &str| finding.fields.iter().find(|field| field.name == name).unwrap_or_else(|| panic!("no {name}: {:#?}", finding.fields));
        assert_eq!((field("sectors per FAT").offset, field("sectors per FAT").value.as_str()), (base + 22, "32"));
        assert_eq!(field("hidden sectors").value, "2048");
        assert_eq!(field("media").value, "0xf8");
        assert_eq!(field("volume serial").value, "1234-ABCD");
        assert_eq!(field("FAT type (by cluster count)").value, "FAT16, 8092 clusters of 512 bytes");
        assert_eq!(field("first FAT at").value, format!("{:#x} (volume + 0x800)", base + 0x800));
        let root = 0x800 + 2 * 32 * 512;
        assert_eq!(field("root directory at").value, format!("{:#x} (volume + {root:#x}), 16384 bytes", base + root));
        assert_eq!(field("data area at").value, format!("{:#x} (volume + {:#x}) (cluster 2)", base + root + 16384, root + 16384));
        assert_eq!(finding.title, "FAT16 boot sector");
    }

    #[test]
    fn the_fat_type_is_decided_by_cluster_count_whatever_the_label_says() {
        let (mut disk, _) = crate::embedfs::test_support::fat_disk();
        let base = 63 * SECTOR;
        disk[base + 54..base + 62].copy_from_slice(b"FAT12   ");
        let finding = FatParser.parse(&disk[base..], base).expect("fat");
        assert_eq!(finding.title, "FAT16 boot sector");
        assert!(finding.fields.iter().any(|field| field.name == "filesystem type (label)" && field.value == "FAT12"));
    }

    #[test]
    fn fat_ntfs_and_ext_superblocks_are_recognised() {
        let mut fat = vec![0u8; SECTOR];
        fat[0] = 0xEB;
        fat[2] = 0x90;
        fat[3..11].copy_from_slice(b"MSDOS5.0");
        fat[11..13].copy_from_slice(&512u16.to_le_bytes());
        fat[13] = 8;
        fat[16] = 2;
        fat[32..36].copy_from_slice(&204_800u32.to_le_bytes());
        fat[71..82].copy_from_slice(b"DATA       ");
        fat[82..90].copy_from_slice(b"FAT32   ");
        fat[510] = 0x55;
        fat[511] = 0xAA;
        let finding = FatParser.parse(&fat, 0).expect("fat");
        assert!(finding.detail.starts_with("FAT32, 512 per sector"), "{}", finding.detail);
        assert!(finding.detail.contains("label \"DATA\""), "{}", finding.detail);
        assert!(finding.detail.contains("the layout does not add up"), "no reserved sectors or FAT size: {}", finding.detail);

        let mut ntfs = vec![0u8; SECTOR];
        ntfs[3..11].copy_from_slice(b"NTFS    ");
        ntfs[11..13].copy_from_slice(&512u16.to_le_bytes());
        ntfs[13] = 8;
        ntfs[40..48].copy_from_slice(&1_000_000u64.to_le_bytes());
        ntfs[48..56].copy_from_slice(&786_432u64.to_le_bytes());
        ntfs[510] = 0x55;
        ntfs[511] = 0xAA;
        let finding = NtfsParser.parse(&ntfs, 0).expect("ntfs");
        assert!(finding.detail.contains("MFT at cluster 786432"), "{}", finding.detail);

        let mut ext = vec![0u8; 2048];
        let sb = 1024;
        ext[sb..sb + 4].copy_from_slice(&65536u32.to_le_bytes());
        ext[sb + 4..sb + 8].copy_from_slice(&262_144u32.to_le_bytes());
        ext[sb + 24..sb + 28].copy_from_slice(&2u32.to_le_bytes());
        ext[sb + 56..sb + 58].copy_from_slice(&EXT_MAGIC.to_le_bytes());
        ext[sb + 96..sb + 100].copy_from_slice(&0x40u32.to_le_bytes());
        ext[sb + 120..sb + 124].copy_from_slice(b"root");
        assert!(ExtParser.looks_like(&ext));
        let finding = ExtParser.parse(&ext, 0).expect("ext");
        assert_eq!(finding.start, 1024);
        assert!(finding.detail.starts_with("ext4, 262144 blocks of 4096"), "{}", finding.detail);
    }
}
