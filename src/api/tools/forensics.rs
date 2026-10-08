//! `forensics.*`: the Forensics tool's search for embedded filesystems,
//! opening a file from one, and its file-type map of the document's blocks.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::api::jobs::JobStartedResult;
use crate::api::output::{self, Made, Output, Produced};
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller, OutputKind};
use crate::embedfs::{EntryKind, Filesystem};
use crate::panel_forensics::{self, BlockScan, FilesystemScan};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("forensics.find_filesystems", Job, caller find_filesystems, FilesystemsParams, JobStartedResult, "Start a search of the document (its first 256 MiB) for SquashFS, CramFS, JFFS2, UBI and FAT images (FAT at any 512-byte boundary, so inside a disk's partitions) as a job: each image found, with its files, deleted FAT entries included, is job.finished's result, and in the window they fill Forensics."),
    method!("forensics.open_entry", View, caller open_entry, OpenEntryParams, Made, "Open one file (or volume) of the filesystem image at an offset of the document as a derived document, by its path in the image; a deleted FAT file opens as recovered from its first cluster on. With output, return its bytes or write them to a file (which needs leave to edit) instead.").outputs(&[OutputKind::New, OutputKind::Return, OutputKind::File], OutputKind::New),
    method!("forensics.classify_blocks", Job, caller classify_blocks, ClassifyBlocksParams, JobStartedResult, "Start labelling every block of the document (its first 256 MiB) as padding, text, markup, machine code, compressed, random, raw image, PCM audio or table data as a job: the runs of one class, with the reason for each, are job.finished's result, and in the window they fill Forensics."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    let image = crate::embedfs::test_support::cramfs_image(&[("version", b"1.2.3\n")]);
    vec![
        ("forensics.find_filesystems", json!({})),
        ("forensics.classify_blocks", json!({"block_size": 512})),
        // A document holding a filesystem image, to open a file of.
        ("documents.derive", json!({"data": crate::api::values::encode_bytes(&image, Default::default()), "name": "image.cramfs"})),
        ("forensics.open_entry", json!({"filesystem": 0, "path": "version"})),
        ("documents.open", json!({"doc": "doc-1"})),
    ]
}

/// Parameters of `forensics.find_filesystems`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesystemsParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// Parameters of `forensics.open_entry`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenEntryParams {
    /// Document id, path or "current" (the default): the parent.
    #[serde(default)]
    pub doc: Option<String>,
    /// Document offset of the filesystem image, as forensics.find_filesystems gave it.
    pub filesystem: u64,
    /// The file's path in the image, such as "etc/passwd".
    pub path: String,
    /// Where the file's bytes go: "new" (the default; {"new": {"label": …}}
    /// labels the sheet), "return", or {"file": path}, which needs leave to edit.
    #[serde(default)]
    pub output: Option<Output>,
}

/// Parameters of `forensics.classify_blocks`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassifyBlocksParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Bytes per block, at least 256 (4096 by default).
    #[serde(default)]
    pub block_size: Option<usize>,
}

/// A file, directory or volume in a filesystem image.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FilesystemEntry {
    pub path: String,
    /// "file", "dir", "link", "special" or "volume".
    pub kind: String,
    /// Bytes extracted, and the size the image declares.
    pub size: u64,
    pub declared_size: u64,
    /// Where something went wrong with it, or how a deleted file was recovered.
    pub note: Option<String>,
    /// A deleted entry (FAT keeps them), listed with what could be recovered.
    #[serde(default)]
    pub deleted: bool,
    /// When it was created and last written, as the image records them:
    /// local wall-clock times such as "2026-09-12 08:14:54" (FAT keeps no zone).
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    /// The first cluster its FAT directory entry names.
    #[serde(default)]
    pub first_cluster: Option<u32>,
    /// Document offset of its 32-byte FAT directory entry.
    #[serde(default)]
    pub entry_offset: Option<u64>,
    /// Where its content lies in the document: each run of contiguous
    /// clusters (a deleted file's: its size read on from its first cluster).
    #[serde(default)]
    pub ranges: Vec<DataRange>,
    /// For a deleted file: whether the clusters it was recovered from are
    /// all still free, as reading them as contiguous assumes.
    #[serde(default)]
    pub clusters_free: Option<bool>,
}

/// Bytes of the document an entry's content lies in.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DataRange {
    pub offset: u64,
    pub len: u64,
}

/// A filesystem image found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FilesystemFound {
    /// "SquashFS", "CramFS", "JFFS2", "UBI" or "FAT".
    pub kind: String,
    pub offset: u64,
    pub len: u64,
    pub description: String,
    pub note: Option<String>,
    pub entries: Vec<FilesystemEntry>,
}

/// What `forensics.find_filesystems`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FilesystemsFound {
    pub filesystems: Vec<FilesystemFound>,
}

/// The name of an entry's kind.
pub fn entry_kind(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Directory => "dir",
        EntryKind::Symlink => "link",
        EntryKind::Special => "special",
        EntryKind::Volume => "volume",
    }
}

impl FilesystemsFound {
    fn of(filesystems: &[Filesystem]) -> Self {
        FilesystemsFound {
            filesystems: filesystems
                .iter()
                .map(|filesystem| FilesystemFound {
                    kind: filesystem.kind.label().to_string(),
                    offset: filesystem.offset as u64,
                    len: filesystem.len as u64,
                    description: filesystem.description.clone(),
                    note: filesystem.note.clone(),
                    entries: filesystem
                        .entries
                        .iter()
                        .map(|entry| FilesystemEntry {
                            path: entry.path.clone(),
                            kind: entry_kind(entry.kind).to_string(),
                            size: entry.data.len() as u64,
                            declared_size: entry.declared_size,
                            note: entry.note.clone(),
                            deleted: entry.record.deleted,
                            created: entry.record.created.clone(),
                            modified: entry.record.modified.clone(),
                            first_cluster: entry.record.first_cluster,
                            entry_offset: entry.record.entry_offset.map(|offset| offset as u64),
                            ranges: entry.record.ranges.iter().map(|&(offset, len)| DataRange { offset: offset as u64, len: len as u64 }).collect(),
                            clusters_free: entry.record.clusters_free,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// A run of blocks of one class.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BlockRun {
    pub offset: u64,
    pub len: u64,
    /// Such as "Text" or "Encrypted / random".
    pub class: String,
    pub blocks: usize,
    pub confidence: f32,
    pub reason: String,
}

/// What `forensics.classify_blocks`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BlockClasses {
    /// Bytes classified from the start, and the blocks they made.
    pub scanned_len: u64,
    pub blocks: usize,
    pub runs: Vec<BlockRun>,
}

impl BlockClasses {
    fn of(scan: &BlockScan) -> Self {
        BlockClasses {
            scanned_len: scan.scanned_len as u64,
            blocks: scan.block_count,
            runs: scan
                .runs
                .iter()
                .map(|run| BlockRun { offset: run.offset as u64, len: run.len as u64, class: run.class.label().to_string(), blocks: run.blocks, confidence: run.confidence, reason: run.reason.clone() })
                .collect(),
        }
    }
}

/// `forensics.find_filesystems`: read the document now and search it on a thread.
pub fn find_filesystems(workspace: &mut dyn Workspace, caller: &Caller, params: FilesystemsParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), 0, None, panel_forensics::SCAN_LIMIT, "the document")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_forensics::await_filesystems);
    let key = panel_forensics::DocumentKey { len: workspace::info(workspace, &span.doc)?.len as usize, version: span.version };
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("filesystems", "Embedded filesystems"),
        &span,
        deliver,
        move |_| FilesystemScan { key, filesystems: panel_forensics::filesystems_in(&bytes) },
        |scan| Summary::of(format!("{} filesystems", scan.filesystems.len()), FilesystemsFound::of(&scan.filesystems)),
    ))
}

pub fn open_entry(workspace: &mut dyn Workspace, caller: &Caller, params: OpenEntryParams) -> Result<Made, ApiError> {
    let output = output::chosen("forensics.open_entry", params.output)?;
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.filesystem, None, panel_forensics::SCAN_LIMIT, "the image")?;
    let filesystems = panel_forensics::filesystems_in(&tool_jobs::read(workspace, &span)?);
    let filesystem = filesystems
        .into_iter()
        .find(|filesystem| filesystem.offset == 0)
        .ok_or_else(|| ApiError::not_found(format!("there is no filesystem image at {:#x}; forensics.find_filesystems lists them", span.start)))?;
    let entry = filesystem
        .entries
        .iter()
        .find(|entry| entry.path == params.path)
        .ok_or_else(|| ApiError::not_found(format!("the {} image at {:#x} has no '{}'", filesystem.kind.label(), span.start, params.path)))?;
    if !(entry.kind.has_content() || entry.kind == EntryKind::Symlink && !entry.data.is_empty()) {
        return Err(ApiError::invalid_params(format!("'{}' is a {}, with nothing to open", entry.path, entry_kind(entry.kind))));
    }
    let name = format!("{} › {}@{:#x}/{}", workspace::info(workspace, &span.doc)?.name, filesystem.kind.label(), span.start, entry.path);
    let delivered = output::deliver(workspace, caller, &span.doc, Produced::bytes(entry.data.as_ref().clone(), name), &output)?;
    Made::of(workspace, delivered)
}

/// `forensics.classify_blocks`: read the document now and classify it on a thread.
pub fn classify_blocks(workspace: &mut dyn Workspace, caller: &Caller, params: ClassifyBlocksParams) -> Result<JobStartedResult, ApiError> {
    let block_size = params.block_size.unwrap_or(crate::fragments::DEFAULT_BLOCK_SIZE);
    if block_size < crate::fragments::MIN_BLOCK_SIZE {
        return Err(ApiError::invalid_params(format!("blocks of {block_size} bytes are too small to judge; use at least {}", crate::fragments::MIN_BLOCK_SIZE)));
    }
    let span = tool_jobs::span(workspace, params.doc.as_deref(), 0, None, panel_forensics::SCAN_LIMIT, "the document")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_forensics::await_blocks);
    let key = panel_forensics::DocumentKey { len: workspace::info(workspace, &span.doc)?.len as usize, version: span.version };
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("block-classes", "Block classes"),
        &span,
        deliver,
        move |_| panel_forensics::classify(&bytes, key, block_size),
        |scan| Summary::of(format!("{} runs", scan.runs.len()), BlockClasses::of(scan)),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn blocks_of_text_and_zeros_are_classified_in_runs() {
        let mut bytes = b"The quick brown fox jumps over the lazy dog. ".repeat(200);
        bytes.truncate(8192);
        bytes.extend(vec![0u8; 8192]);
        let mut workspace = workspace_with("mixed.bin", &bytes);
        let status = run_job(&mut workspace, "forensics.classify_blocks", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        let runs = status["result"]["runs"].as_array().unwrap();
        assert_eq!((runs[0]["class"].as_str(), runs[0]["len"].as_u64()), (Some("Text"), Some(8192)), "{runs:?}");
        assert_eq!((runs[1]["class"].as_str(), runs[1]["offset"].as_u64()), (Some("Zeros / padding"), Some(8192)));
        assert_eq!(call(&mut workspace, "forensics.classify_blocks", json!({"block_size": 16})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn a_file_in_an_embedded_cramfs_image_is_found_and_opens_as_a_document() {
        let image = crate::embedfs::test_support::cramfs_image(&[("version", b"1.2.3\n"), ("motd", b"hello")]);
        let mut bytes = vec![0x5Au8; 4096];
        bytes.extend(&image);
        let mut workspace = workspace_with("firmware.bin", &bytes);
        let status = run_job(&mut workspace, "forensics.find_filesystems", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        let filesystem = &status["result"]["filesystems"][0];
        assert_eq!((filesystem["kind"].as_str(), filesystem["offset"].as_u64()), (Some("CramFS"), Some(4096)), "{filesystem}");
        assert!(filesystem["entries"].as_array().unwrap().iter().any(|entry| entry["path"] == "version" && entry["size"] == 6));
        let opened = call(&mut workspace, "forensics.open_entry", json!({"filesystem": 4096, "path": "version"})).unwrap();
        assert_eq!((opened["name"].as_str(), opened["len"].as_u64()), (Some("firmware.bin › CramFS@0x1000/version"), Some(6)));
        assert_eq!(call(&mut workspace, "forensics.open_entry", json!({"doc": "doc-1", "filesystem": 4096, "path": "missing"})).unwrap_err().code, ErrorCode::NotFound);
        let returned = call(&mut workspace, "forensics.open_entry", json!({"doc": "doc-1", "filesystem": 4096, "path": "motd", "output": {"return": {"encoding": "text"}}})).unwrap();
        assert_eq!(returned["output"]["data"], "hello", "a file's bytes returned, with no sheet made");
        assert!(returned.get("id").is_none());
    }

    #[test]
    fn a_deleted_photo_on_a_usb_stick_image_is_listed_and_opens_recovered() {
        let (disk, photo) = crate::embedfs::test_support::fat_disk();
        let mut workspace = workspace_with("usb_stick.dd", &disk);
        let status = run_job(&mut workspace, "forensics.find_filesystems", json!({}));
        let filesystem = &status["result"]["filesystems"][0];
        assert_eq!((filesystem["kind"].as_str(), filesystem["offset"].as_u64()), (Some("FAT"), Some(63 * 512)), "{status}");
        let entries = filesystem["entries"].as_array().unwrap();
        let deleted = entries.iter().find(|entry| entry["deleted"] == true).expect("the deleted photo");
        assert_eq!(deleted["path"], "IMG_20260912_0814.jpg");
        assert_eq!(deleted["note"], crate::embedfs::fat::NOTE_RECOVERED);
        assert_eq!(deleted["modified"], "2026-09-12 08:14:54");
        assert_eq!(deleted["clusters_free"], true, "{deleted}");
        let range = &deleted["ranges"][0];
        let (at, len) = (range["offset"].as_u64().unwrap() as usize, range["len"].as_u64().unwrap() as usize);
        assert_eq!(&disk[at..at + len], photo.as_slice(), "the range is where the photo lies on the disk");
        let entry_at = deleted["entry_offset"].as_u64().unwrap() as usize;
        assert_eq!(disk[entry_at], 0xE5, "the directory entry starts with the deleted mark");
        assert!(deleted["first_cluster"].as_u64().is_some_and(|cluster| cluster >= 2), "{deleted}");
        let opened = call(&mut workspace, "forensics.open_entry", json!({"filesystem": 63 * 512, "path": "IMG_20260912_0814.jpg"})).unwrap();
        assert_eq!(opened["len"].as_u64(), Some(photo.len() as u64));
        let read = call(&mut workspace, "bytes.read", json!({"doc": opened["id"], "start": 0, "len": 16})).unwrap();
        assert_eq!(read["data"].as_str().unwrap(), photo[..16].iter().map(|byte| format!("{byte:02x}")).collect::<String>());
    }

    #[test]
    fn a_document_without_filesystems_has_none_and_nothing_to_open() {
        let mut workspace = workspace_with("plain.bin", &[0x5Au8; 4096]);
        let status = run_job(&mut workspace, "forensics.find_filesystems", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["result"]["filesystems"], json!([]));
        assert_eq!(call(&mut workspace, "forensics.open_entry", json!({"filesystem": 0, "path": "etc/passwd"})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "forensics.open_entry", json!({"filesystem": 9999, "path": "x"})).unwrap_err().code, ErrorCode::OutOfRange);
    }
}
