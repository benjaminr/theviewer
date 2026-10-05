//! UBI (Unsorted Block Images) images: physical erase blocks (PEBs) that each
//! start with an erase-counter header and, when in use, a volume identifier
//! header naming the volume and logical erase block (LEB) they hold.
//!
//! Volumes are listed with their names from the layout volume and exposed as
//! their LEBs in order. UBIFS file extraction from those volumes is not done
//! here; a volume's bytes can be opened and examined on their own.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{Allowance, Entry, EntryKind, Filesystem, FsKind, be_u32, be_u64, slice_at, take_content};

pub(super) const MAGIC: &[u8] = b"UBI#";
const VID_MAGIC: &[u8] = b"UBI!";
/// Both headers are 64 bytes, the last 4 being a CRC of the first 60.
const HEADER_LEN: usize = 64;
const HEADER_CRC_AT: usize = 60;
const SUPPORTED_VERSION: u8 = 1;
/// Erase block sizes tried when finding the PEB size (4 KiB to 4 MiB).
const MIN_PEB_LOG: u32 = 12;
const MAX_PEB_LOG: u32 = 22;
/// Most PEBs walked in one image.
const MAX_PEBS: usize = 1 << 16;
/// The layout volume holding the volume table.
const LAYOUT_VOLUME_ID: u32 = 0x7FFF_EFFF;
const VOLUME_RECORD_LEN: usize = 172;
const VOLUME_RECORD_CRC_AT: usize = 168;
const VOLUME_NAME_AT: usize = 16;
const VOLUME_NAME_MAX: usize = 127;
const MAX_VOLUMES: usize = 128;
/// Volume types in the VID header and volume table.
const VOLUME_DYNAMIC: u8 = 1;
const VOLUME_STATIC: u8 = 2;
/// The value an erased (unwritten) flash byte reads as.
const ERASED: u8 = 0xFF;

/// UBI's CRC-32: Linux `crc32(0xFFFFFFFF, …)` without a final inversion, the
/// bitwise complement of the standard CRC-32.
fn ubi_crc(bytes: &[u8]) -> u32 {
    !crc32fast::hash(bytes)
}

/// Whether a 64-byte header with `magic` at `at` has a valid CRC.
fn header_is_valid(image: &[u8], at: usize, magic: &[u8]) -> bool {
    let Some(header) = slice_at(image, at, HEADER_LEN) else { return false };
    header.starts_with(magic) && header[4] == SUPPORTED_VERSION && be_u32(header, HEADER_CRC_AT) == Some(ubi_crc(&header[..HEADER_CRC_AT]))
}

/// One mapped logical erase block.
#[derive(Clone, Debug)]
struct Leb {
    volume_type: u8,
    /// Bytes of data in this LEB, for static volumes.
    data_size: u32,
    used_blocks: u32,
    data_pad: u32,
    sequence: u64,
    data_at: usize,
    peb: usize,
}

/// A volume from the layout volume's table.
#[derive(Clone, Debug)]
struct VolumeRecord {
    name: String,
    reserved_pebs: u32,
    volume_type: u8,
}

/// The smallest power-of-two PEB size at which a second valid erase-counter
/// header appears, or the whole image when there is only one.
fn detect_peb_size(image: &[u8]) -> usize {
    (MIN_PEB_LOG..=MAX_PEB_LOG).map(|log| 1usize << log).find(|&size| header_is_valid(image, size, MAGIC)).unwrap_or(image.len())
}

/// Read the UBI image at the start of `image` (at `base` in the scanned
/// data).
pub(super) fn read(image: &[u8], base: usize, allowance: &mut Allowance) -> Result<Filesystem, String> {
    if !header_is_valid(image, 0, MAGIC) {
        return Err("not a UBI erase-counter header".to_string());
    }
    let peb_size = detect_peb_size(image);
    let (lebs, peb_count) = walk_pebs(image, peb_size);
    let len = (peb_count * peb_size).min(image.len());
    let table = lebs.get(&(LAYOUT_VOLUME_ID, 0)).map(|leb| volume_table(image, leb, peb_size)).unwrap_or_default();
    let mut volume_ids: Vec<u32> = lebs.keys().map(|&(volume, _)| volume).filter(|&volume| volume != LAYOUT_VOLUME_ID).collect();
    volume_ids.extend(table.keys().copied());
    volume_ids.sort_unstable();
    volume_ids.dedup();
    let mut entries = Vec::new();
    for volume in volume_ids.into_iter().take(allowance.max_entries()) {
        entries.push(volume_entry(image, base, volume, table.get(&volume), &lebs, peb_size, allowance));
    }
    let mapped = lebs.len();
    let description = format!("UBI, {} KiB erase blocks, {peb_count} blocks ({mapped} mapped), {} volumes", peb_size / 1024, entries.len());
    let note = Some("UBIFS contents are not extracted; volumes are exposed as raw LEB data".to_string());
    Ok(Filesystem { kind: FsKind::Ubi, offset: base, len, description, entries, note })
}

/// Every PEB from the start: the newest copy of each (volume, LEB) and how
/// many PEBs belong to the image.
fn walk_pebs(image: &[u8], peb_size: usize) -> (BTreeMap<(u32, u32), Leb>, usize) {
    let mut lebs: BTreeMap<(u32, u32), Leb> = BTreeMap::new();
    let mut count = 0;
    while count < MAX_PEBS {
        let at = count * peb_size;
        if at >= image.len() {
            break;
        }
        if !header_is_valid(image, at, MAGIC) {
            let erased = image[at..].iter().take(HEADER_LEN).all(|&byte| byte == ERASED);
            if !erased {
                break;
            }
            count += 1;
            continue;
        }
        count += 1;
        let Some((volume, number, leb)) = parse_vid(image, at, peb_size) else { continue };
        if lebs.get(&(volume, number)).is_none_or(|existing| existing.sequence < leb.sequence) {
            lebs.insert((volume, number), leb);
        }
    }
    (lebs, count)
}

/// The VID header of the PEB at `at`, when it is mapped.
fn parse_vid(image: &[u8], at: usize, peb_size: usize) -> Option<(u32, u32, Leb)> {
    let vid_offset = be_u32(image, at + 16)? as usize;
    let data_offset = be_u32(image, at + 20)? as usize;
    if vid_offset + HEADER_LEN > peb_size || data_offset >= peb_size {
        return None;
    }
    let vid_at = at + vid_offset;
    if !header_is_valid(image, vid_at, VID_MAGIC) {
        return None;
    }
    let leb = Leb {
        volume_type: *image.get(vid_at + 5)?,
        data_size: be_u32(image, vid_at + 20)?,
        used_blocks: be_u32(image, vid_at + 24)?,
        data_pad: be_u32(image, vid_at + 28)?,
        sequence: be_u64(image, vid_at + 40)?,
        data_at: at + data_offset,
        peb: at,
    };
    Some((be_u32(image, vid_at + 8)?, be_u32(image, vid_at + 12)?, leb))
}

/// Usable bytes in one LEB of a volume.
fn leb_size(leb: &Leb, peb_size: usize) -> usize {
    (leb.peb + peb_size).saturating_sub(leb.data_at).saturating_sub(leb.data_pad as usize)
}

/// The volume table held in the layout volume, keyed by volume id.
fn volume_table(image: &[u8], layout: &Leb, peb_size: usize) -> BTreeMap<u32, VolumeRecord> {
    let mut table = BTreeMap::new();
    let Some(data) = slice_at(image, layout.data_at, leb_size(layout, peb_size)) else { return table };
    for (index, record) in data.as_chunks::<VOLUME_RECORD_LEN>().0.iter().take(MAX_VOLUMES).enumerate() {
        let reserved_pebs = be_u32(record, 0).unwrap_or(0);
        let crc_ok = be_u32(record, VOLUME_RECORD_CRC_AT) == Some(ubi_crc(&record[..VOLUME_RECORD_CRC_AT]));
        if reserved_pebs == 0 || !crc_ok {
            continue;
        }
        let name_len = (u16::from_be_bytes([record[14], record[15]]) as usize).min(VOLUME_NAME_MAX);
        let name = super::clean_name(&record[VOLUME_NAME_AT..VOLUME_NAME_AT + name_len]).unwrap_or_else(|| format!("volume {index}"));
        table.insert(index as u32, VolumeRecord { name, reserved_pebs, volume_type: record[12] });
    }
    table
}

/// One volume's LEBs in order: unmapped LEBs of dynamic volumes read as
/// erased flash; static volumes stop at their used block count and size.
fn volume_entry(image: &[u8], base: usize, volume: u32, record: Option<&VolumeRecord>, lebs: &BTreeMap<(u32, u32), Leb>, peb_size: usize, allowance: &mut Allowance) -> Entry {
    let mapped: Vec<(u32, &Leb)> = lebs.range((volume, 0)..=(volume, u32::MAX)).map(|(&(_, number), leb)| (number, leb)).collect();
    let name = record.map_or_else(|| format!("volume {volume}"), |record| record.name.clone());
    let volume_type = record.map(|record| record.volume_type).or(mapped.first().map(|(_, leb)| leb.volume_type)).unwrap_or(VOLUME_DYNAMIC);
    let cap = allowance.cap().unwrap_or(0);
    let mut content = Vec::new();
    let mut declared = 0u64;
    if let Some(&(_, first)) = mapped.first() {
        let block_len = leb_size(first, peb_size);
        let block_count = match volume_type {
            VOLUME_STATIC => first.used_blocks as usize,
            _ => mapped.last().map_or(0, |&(number, _)| number as usize + 1),
        };
        declared = record.map_or(block_count as u64, |record| record.reserved_pebs as u64) * block_len as u64;
        let by_number: BTreeMap<u32, &Leb> = mapped.iter().copied().collect();
        for number in 0..block_count.min(MAX_PEBS) {
            if content.len() >= cap {
                break;
            }
            let room = cap - content.len();
            match by_number.get(&(number as u32)) {
                Some(leb) => {
                    let useful = if volume_type == VOLUME_STATIC { (leb.data_size as usize).min(block_len) } else { block_len };
                    let bytes = slice_at(image, leb.data_at, useful).unwrap_or_default();
                    content.extend_from_slice(&bytes[..bytes.len().min(room)]);
                }
                None => content.resize(content.len() + block_len.min(room), ERASED),
            }
        }
    }
    let (data, note) = take_content(content, declared, allowance);
    let first_peb = mapped.first().map_or(0, |(_, leb)| leb.peb);
    let kind_label = if volume_type == VOLUME_STATIC { "static" } else { "dynamic" };
    Entry {
        path: name,
        kind: EntryKind::Volume,
        declared_size: declared,
        data: Arc::new(data),
        source_offset: base + first_peb,
        source_len: mapped.len() * peb_size,
        method: None,
        note: note.or_else(|| Some(format!("{kind_label} volume {volume}, {} LEBs mapped", mapped.len()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unpack::Limits;

    const PEB: usize = 8192;
    const VID_OFFSET: usize = 64;
    const DATA_OFFSET: usize = 128;
    const LEB: usize = PEB - DATA_OFFSET;

    fn seal(header: &mut [u8]) {
        let crc = ubi_crc(&header[..HEADER_CRC_AT]);
        header[HEADER_CRC_AT..HEADER_LEN].copy_from_slice(&crc.to_be_bytes());
    }

    /// One PEB holding `data` as LEB `number` of `volume`.
    fn peb(volume: u32, number: u32, sequence: u64, volume_type: u8, data: &[u8]) -> Vec<u8> {
        let mut block = vec![ERASED; PEB];
        let ec = &mut block[..HEADER_LEN];
        ec.fill(0);
        ec[..4].copy_from_slice(MAGIC);
        ec[4] = SUPPORTED_VERSION;
        ec[16..20].copy_from_slice(&(VID_OFFSET as u32).to_be_bytes());
        ec[20..24].copy_from_slice(&(DATA_OFFSET as u32).to_be_bytes());
        seal(ec);
        let vid = &mut block[VID_OFFSET..VID_OFFSET + HEADER_LEN];
        vid.fill(0);
        vid[..4].copy_from_slice(VID_MAGIC);
        vid[4] = SUPPORTED_VERSION;
        vid[5] = volume_type;
        vid[8..12].copy_from_slice(&volume.to_be_bytes());
        vid[12..16].copy_from_slice(&number.to_be_bytes());
        vid[20..24].copy_from_slice(&(data.len() as u32).to_be_bytes());
        vid[24..28].copy_from_slice(&1u32.to_be_bytes());
        vid[40..48].copy_from_slice(&sequence.to_be_bytes());
        seal(vid);
        block[DATA_OFFSET..DATA_OFFSET + data.len()].copy_from_slice(data);
        block
    }

    fn volume_table_leb(volumes: &[(&str, u8)]) -> Vec<u8> {
        let mut table = Vec::new();
        for (name, volume_type) in volumes {
            let mut record = vec![0u8; VOLUME_RECORD_LEN];
            record[0..4].copy_from_slice(&4u32.to_be_bytes());
            record[4..8].copy_from_slice(&1u32.to_be_bytes());
            record[12] = *volume_type;
            record[14..16].copy_from_slice(&(name.len() as u16).to_be_bytes());
            record[VOLUME_NAME_AT..VOLUME_NAME_AT + name.len()].copy_from_slice(name.as_bytes());
            let crc = ubi_crc(&record[..VOLUME_RECORD_CRC_AT]);
            record[VOLUME_RECORD_CRC_AT..].copy_from_slice(&crc.to_be_bytes());
            table.extend_from_slice(&record);
        }
        table
    }

    fn sample_image() -> Vec<u8> {
        let table = volume_table_leb(&[("rootfs", VOLUME_DYNAMIC), ("kernel", VOLUME_STATIC)]);
        let mut image = Vec::new();
        image.extend(peb(LAYOUT_VOLUME_ID, 0, 1, VOLUME_DYNAMIC, &table));
        image.extend(peb(0, 1, 3, VOLUME_DYNAMIC, &[b'B'; LEB]));
        image.extend(peb(0, 0, 2, VOLUME_DYNAMIC, &[b'a'; LEB]));
        image.extend(peb(0, 0, 9, VOLUME_DYNAMIC, &[b'A'; LEB])); // A newer copy of LEB 0.
        image.extend(peb(1, 0, 4, VOLUME_STATIC, b"kernel image"));
        image.extend(vec![ERASED; PEB]); // An erased PEB.
        image.extend(vec![0x11; 300]); // Not UBI.
        image
    }

    #[test]
    fn volumes_are_listed_by_name_with_their_lebs_in_order() {
        let image = sample_image();
        let mut left = usize::MAX;
        let filesystem = read(&image, 0, &mut Allowance::new(&Limits::default(), &mut left)).unwrap();
        assert_eq!(filesystem.len, 6 * PEB);
        assert!(filesystem.description.starts_with("UBI, 8 KiB erase blocks, 6 blocks"), "{}", filesystem.description);
        let names: Vec<&str> = filesystem.entries.iter().map(|entry| entry.path.as_str()).collect();
        assert_eq!(names, ["rootfs", "kernel"]);
        let rootfs = &filesystem.entries[0];
        assert_eq!(rootfs.kind, EntryKind::Volume);
        assert_eq!(rootfs.data.len(), 2 * LEB);
        assert!(rootfs.data[..LEB].iter().all(|&byte| byte == b'A'), "the newest copy of LEB 0 wins");
        assert!(rootfs.data[LEB..].iter().all(|&byte| byte == b'B'));
        assert_eq!(filesystem.entries[1].data.as_slice(), b"kernel image");
    }

    #[test]
    fn volume_bytes_are_charged_to_the_allowance() {
        let image = sample_image();
        let mut left = LEB + 10;
        let filesystem = read(&image, 0, &mut Allowance::new(&Limits::default(), &mut left)).unwrap();
        assert_eq!(filesystem.entries[0].data.len(), LEB + 10);
        assert!(filesystem.entries[1].data.is_empty());
        assert_eq!(left, 0);
    }

    #[test]
    fn damaged_images_do_not_panic() {
        let image = sample_image();
        let noise = super::super::test_support::noise(image.len(), 13);
        for step in [5, 17, 61, 255, 1001] {
            let mut damaged = image.clone();
            for index in (0..damaged.len()).step_by(step) {
                damaged[index] ^= noise[index];
            }
            let mut left = 1 << 20;
            let _ = read(&damaged, 0, &mut Allowance::new(&Limits::default(), &mut left));
        }
        for cut in [10, 64, PEB + 70, 3 * PEB / 2] {
            let mut left = usize::MAX;
            let _ = read(&image[..cut], 0, &mut Allowance::new(&Limits::default(), &mut left));
        }
    }
}
