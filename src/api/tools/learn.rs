//! `learn.*`: learning a signature and a template from sample files, and
//! finding files that resemble the document by fuzzy hash and shared
//! fragments, as the Learn tool does. The document is always the first
//! sample and the file the others are compared with.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller};
use crate::bus::JobHandle;
use crate::fuzzy::{self, SharedFragment};
use crate::learn::{self, LearnedFormat, Sample};
use crate::panel_learn::{ComparedFile, LoadedFile, read_file};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("learn.format", Job, caller format, FormatParams, JobStartedResult, "Start learning what the document and sample files of the same format share (a magic number, header fields) as a background job; a signature for the catalogue and a template draft are job.finished's result, and in the window the Learn tool shows them."),
    method!("learn.save_catalogue", Edit, caller save_catalogue, SaveCatalogueParams, SaveCatalogueResult, "Write a learned signature to a new file in the user's catalogue folder, never over another, and load it.").writes_file(crate::api::WritesFile::Always),
    method!("learn.fuzzy_compare", Job, caller fuzzy_compare, FuzzyCompareParams, JobStartedResult, "Start hashing files with ssdeep and scoring how like the document each is, 0 to 100, as a background job; the scores are job.finished's result, and in the window the Learn tool lists them."),
    method!("learn.fragments", Job, caller fragments, FragmentsParams, JobStartedResult, "Start finding the blocks of the document that also occur in a file, as a background job; the shared fragments are job.finished's result, and in the window the Learn tool lists them."),
];

/// An example call of each of [`METHODS`].
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    let sample = crate::api::test_support::example_file().display().to_string();
    vec![
        ("learn.format", json!({"paths": [sample]})),
        ("learn.save_catalogue", json!({"id": "user/learned-example", "toml": "[[signature]]\nid = \"user/learned-example\"\n"})),
        ("learn.fuzzy_compare", json!({"paths": [sample]})),
        ("learn.fragments", json!({"path": sample, "block": 64})),
    ]
}

/// What a call to one of this module's methods would do, in plain words.
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    match method {
        "learn.save_catalogue" => Some(format!("Save the signature {} to your catalogue", params.get("id")?.as_str()?)),
        _ => None,
    }
}

/// Largest part of each file (and of the document) that is read.
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
/// Most files one call reads.
pub const MOST_FILES: usize = 64;
/// Most numbered variants tried when a catalogue file name is taken.
const MAX_FILE_NAME_ATTEMPTS: usize = 1000;
/// Smallest and largest fragment block.
const FRAGMENT_BLOCKS: std::ops::RangeInclusive<usize> = 16..=65_536;

/// Parameters of `learn.format`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FormatParams {
    /// Document id, path or "current" (left out: the caller's focus): the first sample.
    #[serde(default)]
    pub doc: Option<String>,
    /// The other samples, files of the same format.
    pub paths: Vec<PathBuf>,
}

/// What `learn.format`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FormatResult {
    /// Catalogue id, such as "user/learned-51584631".
    pub id: String,
    pub name: String,
    pub sample_count: usize,
    /// Leading bytes compared in every sample.
    pub compared_len: usize,
    /// A `[[signature]]` entry for the catalogue, to save with learn.save_catalogue.
    pub catalogue_toml: String,
    /// A template draft of the header, for templates.apply.
    pub template: String,
    /// What is constant and what varies, in words.
    pub summary: String,
}

impl FormatResult {
    pub fn of(learned: &LearnedFormat) -> Self {
        FormatResult {
            id: learned.id.clone(),
            name: learned.name.clone(),
            sample_count: learned.sample_count,
            compared_len: learned.compared_len,
            catalogue_toml: learned.catalogue_toml.clone(),
            template: learned.template.clone(),
            summary: learned.summary.clone(),
        }
    }
}

/// Parameters of `learn.save_catalogue`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveCatalogueParams {
    /// Catalogue id the file is named after, such as "user/learned-51584631".
    pub id: String,
    /// The catalogue entry, as learn.format gives it.
    pub toml: String,
}

/// The result of `learn.save_catalogue`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SaveCatalogueResult {
    /// The file written.
    pub path: String,
}

/// Parameters of `learn.fuzzy_compare`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FuzzyCompareParams {
    /// Document id, path or "current" (left out: the caller's focus): what the files are compared with.
    #[serde(default)]
    pub doc: Option<String>,
    /// The files to compare.
    pub paths: Vec<PathBuf>,
}

/// One file compared with the document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComparedResult {
    pub path: String,
    /// The file's full length.
    pub size: u64,
    /// Its ssdeep hash.
    pub hash: String,
    /// How like the document it is, 0 to 100.
    pub score: u32,
}

/// What `learn.fuzzy_compare`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FuzzyCompareResult {
    /// The document's ssdeep hash.
    pub document_hash: String,
    /// The files that could be read, in the order given.
    pub files: Vec<ComparedResult>,
    /// Why the others could not.
    pub problems: Vec<String>,
}

/// Parameters of `learn.fragments`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FragmentsParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// The file to look in.
    pub path: PathBuf,
    /// Block size in bytes, 16 to 65536 (512 by default); shared runs are
    /// found a whole block at a time.
    #[serde(default)]
    pub block: Option<usize>,
}

/// A run of bytes found in both the document and the file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FragmentResult {
    pub offset_here: usize,
    pub offset_there: usize,
    pub len: usize,
}

/// What `learn.fragments`' job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FragmentsResult {
    pub path: String,
    pub block: usize,
    pub fragments: Vec<FragmentResult>,
}

/// A document as a sample: which it is, and its leading bytes.
struct DocumentSample {
    id: String,
    version: u64,
    /// Up to [`MAX_FILE_BYTES`] of it.
    bytes: Arc<[u8]>,
    /// Its full length.
    len: u64,
}

/// The document `doc` names, as a sample.
fn document_sample(workspace: &mut dyn Workspace, doc: Option<&str>) -> Result<DocumentSample, ApiError> {
    let id = workspace::resolve(workspace, doc)?;
    let version = workspace::info(workspace, &id)?.version;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let len = document.len() as u64;
    Ok(DocumentSample { id, version, bytes: document.read_range(0, MAX_FILE_BYTES).into(), len })
}

/// Refuse more than [`MOST_FILES`] paths, or a path that is not a file.
fn check_paths(paths: &[PathBuf]) -> Result<(), ApiError> {
    if paths.len() > MOST_FILES {
        return Err(ApiError::too_large(format!("{} files is over the limit of {MOST_FILES} for one call", paths.len())));
    }
    match paths.iter().find(|path| !path.is_file()) {
        Some(missing) => Err(ApiError::not_found(format!("there is no file at {}", missing.display()))),
        None => Ok(()),
    }
}

/// Read the sample files and learn what they and `document` share, and
/// finish `job` with it.
pub(crate) fn run_learning(document: Arc<[u8]>, document_len: u64, paths: &[PathBuf], job: &JobHandle) -> Result<LearnedFormat, String> {
    let learned = paths.iter().map(|path| read_file(path)).collect::<Result<Vec<LoadedFile>, String>>().and_then(|files| {
        let samples: Vec<Sample> = std::iter::once(Sample { bytes: &document, file_len: document_len })
            .chain(files.iter().map(|file| Sample { bytes: &file.bytes, file_len: file.file_len }))
            .collect();
        learn::learn_format(&samples).map_err(|error| format!("Could not learn a format: {error}."))
    });
    match &learned {
        Ok(format) => job.finish_with(true, format!("learned {}", format.id), serde_json::to_value(FormatResult::of(format)).ok()),
        Err(message) => job.finish(false, message.clone()),
    }
    learned
}

/// Read and hash the files, score them against `document`, and finish
/// `job` with the scores.
pub(crate) fn run_comparison(document: &[u8], paths: &[PathBuf], job: &JobHandle) -> Vec<Result<ComparedFile, String>> {
    let document_hash = fuzzy::fuzzy_hash(document);
    let compared: Vec<Result<ComparedFile, String>> = paths
        .iter()
        .map(|path| {
            let file = read_file(path)?;
            let hash = fuzzy::fuzzy_hash(&file.bytes);
            Ok(ComparedFile { file, hash })
        })
        .collect();
    let files = compared
        .iter()
        .flatten()
        .map(|compared| ComparedResult {
            path: compared.file.path.display().to_string(),
            size: compared.file.file_len,
            hash: compared.hash.to_string(),
            score: fuzzy::compare(&document_hash, &compared.hash),
        })
        .collect::<Vec<_>>();
    let problems = compared.iter().filter_map(|result| result.as_ref().err().cloned()).collect();
    let result = FuzzyCompareResult { document_hash: document_hash.to_string(), files, problems };
    job.finish_with(!result.files.is_empty(), format!("{} files compared", result.files.len()), serde_json::to_value(&result).ok());
    compared
}

/// Find the blocks of `here` that occur in the file at `path`, and finish
/// `job` with them. Returns the file's name and the fragments.
pub(crate) fn run_fragments(here: &[u8], path: &Path, block: usize, job: &JobHandle) -> Result<(String, Vec<SharedFragment>), String> {
    let found = read_file(path).and_then(|file| fuzzy::shared_fragments(here, &file.bytes, block).map(|fragments| (file.name, fragments)).map_err(|error| error.to_string()));
    match &found {
        Ok((_, fragments)) => {
            let result = FragmentsResult {
                path: path.display().to_string(),
                block,
                fragments: fragments.iter().map(|fragment| FragmentResult { offset_here: fragment.offset_here, offset_there: fragment.offset_there, len: fragment.len }).collect(),
            };
            job.finish_with(true, format!("{} shared fragments", fragments.len()), serde_json::to_value(result).ok());
        }
        Err(message) => job.finish(false, message.clone()),
    }
    found
}

/// Whether document `id` is the one the window shows.
fn shown_in_window(workspace: &mut dyn Workspace, id: &str) -> bool {
    workspace.window().is_some_and(|app| app.document_id() == id)
}

pub fn format(workspace: &mut dyn Workspace, caller: &Caller, params: FormatParams) -> Result<JobStartedResult, ApiError> {
    check_paths(&params.paths)?;
    if params.paths.is_empty() {
        return Err(ApiError::invalid_params("give at least one sample file beside the document"));
    }
    let DocumentSample { id, version, bytes: document, len: document_len } = document_sample(workspace, params.doc.as_deref())?;
    if document_len == 0 {
        return Err(ApiError::invalid_params("the document is empty, so it cannot be a sample"));
    }
    if shown_in_window(workspace, &id)
        && let Some(app) = workspace.window()
    {
        return Ok(JobStartedResult::started(crate::panel_learn::learn_as(app, params.paths, &caller.producer())));
    }
    let job = workspace.bus().start_job("learn", "Learning a format", caller.producer(), Some((id, version)));
    let started = JobStartedResult::started(job.id().to_string());
    std::thread::spawn(move || run_learning(document, document_len, &params.paths, &job));
    Ok(started)
}

pub fn fuzzy_compare(workspace: &mut dyn Workspace, caller: &Caller, params: FuzzyCompareParams) -> Result<JobStartedResult, ApiError> {
    check_paths(&params.paths)?;
    let DocumentSample { id, version, bytes: document, .. } = document_sample(workspace, params.doc.as_deref())?;
    if shown_in_window(workspace, &id)
        && let Some(app) = workspace.window()
    {
        return Ok(JobStartedResult::started(crate::panel_learn::compare_as(app, params.paths, &caller.producer())));
    }
    let job = workspace.bus().start_job("fuzzy-compare", "Comparing files", caller.producer(), Some((id, version)));
    let started = JobStartedResult::started(job.id().to_string());
    std::thread::spawn(move || run_comparison(&document, &params.paths, &job));
    Ok(started)
}

pub fn fragments(workspace: &mut dyn Workspace, caller: &Caller, params: FragmentsParams) -> Result<JobStartedResult, ApiError> {
    let block = params.block.unwrap_or(fuzzy::DEFAULT_FRAGMENT_BLOCK);
    if !FRAGMENT_BLOCKS.contains(&block) {
        return Err(ApiError::invalid_params(format!("a block of {block} bytes is outside 16 to 65536")));
    }
    check_paths(std::slice::from_ref(&params.path))?;
    let DocumentSample { id, version, bytes: document, .. } = document_sample(workspace, params.doc.as_deref())?;
    if shown_in_window(workspace, &id)
        && let Some(app) = workspace.window()
    {
        return Ok(JobStartedResult::started(crate::panel_learn::fragments_as(app, params.path, block, &caller.producer())));
    }
    let job = workspace.bus().start_job("fragments", "Finding shared fragments", caller.producer(), Some((id, version)));
    let started = JobStartedResult::started(job.id().to_string());
    std::thread::spawn(move || run_fragments(&document, &params.path, block, &job));
    Ok(started)
}

/// The folder learned signatures are saved in: the user's catalogue
/// folder, or a scratch folder while testing.
fn catalogue_dir() -> Option<PathBuf> {
    #[cfg(test)]
    return Some(std::env::temp_dir().join(format!("theviewer-catalogue-{}", std::process::id())));
    #[cfg(not(test))]
    crate::app::user_catalog_dir()
}

/// A file name stem from a catalogue id: `user/learned-5158` → `learned-5158`.
pub fn file_stem_for(id: &str) -> String {
    let last = id.rsplit('/').next().unwrap_or(id);
    let stem: String = last.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    if stem.is_empty() { "learned".to_string() } else { stem }
}

/// Write `toml` to a new file in `dir`, named after `id`, adding `-2`, `-3`
/// and so on rather than overwriting an existing file.
pub fn write_new_catalogue_file(dir: &Path, id: &str, toml: &str) -> Result<PathBuf, String> {
    use std::fs::OpenOptions;
    use std::io::{ErrorKind, Write};
    std::fs::create_dir_all(dir).map_err(|error| format!("Could not create {}: {error}", dir.display()))?;
    let stem = file_stem_for(id);
    for attempt in 1..=MAX_FILE_NAME_ATTEMPTS {
        let name = if attempt == 1 { format!("{stem}.toml") } else { format!("{stem}-{attempt}.toml") };
        let path = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(toml.as_bytes()).map_err(|error| format!("Could not write {}: {error}", path.display()))?;
                return Ok(path);
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("Could not create {}: {error}", path.display())),
        }
    }
    Err(format!("{} already holds {MAX_FILE_NAME_ATTEMPTS} files named {stem}; remove some first", dir.display()))
}

pub fn save_catalogue(workspace: &mut dyn Workspace, _caller: &Caller, params: SaveCatalogueParams) -> Result<SaveCatalogueResult, ApiError> {
    if let Err(error) = params.toml.parse::<toml::Table>() {
        return Err(ApiError::invalid_params(format!("the catalogue entry is not TOML: {error}")));
    }
    let dir = catalogue_dir().ok_or_else(|| ApiError::new(crate::api::ErrorCode::Unavailable, "Could not find your catalogue folder: HOME is not set."))?;
    let path = write_new_catalogue_file(&dir, &params.id, &params.toml).map_err(|message| ApiError::new(crate::api::ErrorCode::Unavailable, message))?;
    if let Some(app) = workspace.window() {
        app.reload_plugins();
    }
    Ok(SaveCatalogueResult { path: path.display().to_string() })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};
    use crate::api::tools::finished_job as finished;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("theviewer-learn-api-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A "QXF1" file: magic, version, u32 LE total length, varied body.
    pub(crate) fn qxf_sample(version: u8, total_len: usize) -> Vec<u8> {
        let mut bytes = b"QXF1".to_vec();
        bytes.push(version);
        bytes.extend_from_slice(&(total_len as u32).to_le_bytes());
        let mut state = total_len as u32 | 1;
        while bytes.len() < total_len {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            bytes.push((state >> 16) as u8);
        }
        bytes
    }

    #[test]
    fn a_format_is_learned_from_the_document_and_sample_files() {
        let dir = scratch_dir("format");
        let (two, three) = (dir.join("two.qxf"), dir.join("three.qxf"));
        std::fs::write(&two, qxf_sample(2, 7000)).unwrap();
        std::fs::write(&three, qxf_sample(3, 5100)).unwrap();
        let mut workspace = workspace_with("one.qxf", &qxf_sample(1, 6000));
        let started = call(&mut workspace, "learn.format", json!({"paths": [two, three]})).unwrap();
        let status = finished(&mut workspace, &started);
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["result"]["id"], "user/learned-51584631");
        assert_eq!(status["result"]["sample_count"], 3);
        assert!(status["result"]["template"].as_str().unwrap().contains("struct"));
        assert_eq!(call(&mut workspace, "learn.format", json!({"paths": []})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "learn.format", json!({"paths": [dir.join("missing.qxf")]})).unwrap_err().code, ErrorCode::NotFound);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn files_are_scored_by_fuzzy_hash_and_their_shared_fragments_found() {
        let dir = scratch_dir("fuzzy");
        let document = qxf_sample(1, 6000);
        let mut related = vec![0x5Au8; 300];
        related.extend_from_slice(&document[1024..5120]);
        let (related_path, other_path) = (dir.join("related.bin"), dir.join("other.bin"));
        std::fs::write(&related_path, &related).unwrap();
        std::fs::write(&other_path, qxf_sample(9, 3000)).unwrap();
        let mut workspace = workspace_with("one.qxf", &document);
        let started = call(&mut workspace, "learn.fuzzy_compare", json!({"paths": [related_path, other_path]})).unwrap();
        let status = finished(&mut workspace, &started);
        let files = status["result"]["files"].as_array().unwrap();
        assert_eq!(files.len(), 2, "{status}");
        assert!(files[0]["score"].as_u64().unwrap() > files[1]["score"].as_u64().unwrap(), "{status}");
        let started = call(&mut workspace, "learn.fragments", json!({"path": related_path})).unwrap();
        let status = finished(&mut workspace, &started);
        assert_eq!(status["result"]["fragments"], json!([{"offset_here": 1024, "offset_there": 300, "len": 4096}]));
        assert_eq!(call(&mut workspace, "learn.fragments", json!({"path": related_path, "block": 4})).unwrap_err().code, ErrorCode::InvalidParams);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_learned_signature_is_saved_beside_the_others_never_over_them() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let entry = "[[signature]]\nid = \"user/learned-test-save\"\n";
        let first = call(&mut workspace, "learn.save_catalogue", json!({"id": "user/learned-test-save", "toml": entry})).unwrap();
        let second = call(&mut workspace, "learn.save_catalogue", json!({"id": "user/learned-test-save", "toml": entry})).unwrap();
        assert_ne!(first["path"], second["path"]);
        assert_eq!(std::fs::read_to_string(first["path"].as_str().unwrap()).unwrap(), entry);
        assert_eq!(call(&mut workspace, "learn.save_catalogue", json!({"id": "x", "toml": "not = = toml"})).unwrap_err().code, ErrorCode::InvalidParams);
        for saved in [&first, &second] {
            let _ = std::fs::remove_file(saved["path"].as_str().unwrap());
        }
    }

    #[test]
    fn catalogue_files_are_named_after_the_id_and_never_overwritten() {
        let dir = scratch_dir("save");
        let first = write_new_catalogue_file(&dir, "user/learned-51584631", "one").unwrap();
        let second = write_new_catalogue_file(&dir, "user/learned-51584631", "two").unwrap();
        assert_eq!(first.file_name().unwrap(), "learned-51584631.toml");
        assert_eq!(second.file_name().unwrap(), "learned-51584631-2.toml");
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "one");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "two");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn odd_ids_still_give_safe_file_names() {
        assert_eq!(file_stem_for("user/learned-ab"), "learned-ab");
        assert_eq!(file_stem_for("../../etc"), "etc");
        assert_eq!(file_stem_for("a b/c:d"), "c-d");
        assert_eq!(file_stem_for(""), "learned");
    }
}
