//! Live data sources, watch mode and recording.
//!
//! * [`SourceSpec`] parses what the user typed into "open" (a path, a URL,
//!   `serial:/dev/…@baud`, a block device or `pid:1234`).
//! * [`fetch_url`], [`read_block_device`] and the process-memory functions
//!   turn a source into bytes.
//! * [`SerialCapture`] collects bytes from a serial port on a background thread.
//! * [`FileWatcher`] notices when a file on disk grows or is rewritten.
//! * [`Recording`] keeps a memory-bounded history of a changing document.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

/// Default serial speed when none is given.
pub const DEFAULT_BAUD: u32 = 115_200;
/// Most bytes a serial capture keeps before it stops.
pub const SERIAL_CAPTURE_LIMIT: usize = 256 * 1024 * 1024;
/// Default memory budget for a [`Recording`].
pub const DEFAULT_RECORDING_BUDGET: usize = 256 * 1024 * 1024;

const URL_TIMEOUT: Duration = Duration::from_secs(30);
const READ_CHUNK: usize = 1024 * 1024;
const NOT_LINUX_MESSAGE: &str = "Reading process memory is only supported on Linux; macOS requires the com.apple.security.cs.debugger entitlement and SIP restrictions apply";

// ---------------------------------------------------------------------------
// Source specifications
// ---------------------------------------------------------------------------

/// Where bytes come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceSpec {
    File(PathBuf),
    Url(String),
    Serial { port: String, baud: u32 },
    BlockDevice(PathBuf),
    Process { pid: u32 },
}

impl SourceSpec {
    /// Interpret what the user typed.
    pub fn parse(text: &str) -> Result<SourceSpec, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("Type a path, a URL, serial:/dev/… or pid:1234".to_string());
        }
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            return Ok(SourceSpec::Url(text.to_string()));
        }
        if let Some(rest) = strip_prefix_ignore_case(text, "serial:") {
            return parse_serial(rest);
        }
        if let Some(rest) = strip_prefix_ignore_case(text, "pid:") {
            let pid = rest.trim().parse::<u32>().map_err(|_| format!("'{rest}' is not a process id"))?;
            return Ok(SourceSpec::Process { pid });
        }
        let path = PathBuf::from(text);
        if is_block_device_path(&path) {
            return Ok(SourceSpec::BlockDevice(path));
        }
        Ok(SourceSpec::File(path))
    }

    /// A short human description, e.g. "serial port /dev/cu.usbserial at 115200 baud".
    pub fn describe(&self) -> String {
        match self {
            SourceSpec::File(path) => format!("file {}", path.display()),
            SourceSpec::Url(url) => format!("URL {url}"),
            SourceSpec::Serial { port, baud } => format!("serial port {port} at {baud} baud"),
            SourceSpec::BlockDevice(path) => format!("block device {}", path.display()),
            SourceSpec::Process { pid } => format!("memory of process {pid}"),
        }
    }
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &text[prefix.len()..])
}

fn parse_serial(rest: &str) -> Result<SourceSpec, String> {
    let (port, baud) = match rest.rsplit_once('@') {
        Some((port, baud)) => {
            let baud = baud.trim().parse::<u32>().map_err(|_| format!("'{baud}' is not a baud rate"))?;
            (port, baud)
        }
        None => (rest, DEFAULT_BAUD),
    };
    let port = port.trim();
    if port.is_empty() {
        return Err("serial: needs a port, e.g. serial:/dev/cu.usbserial-1420@115200".to_string());
    }
    Ok(SourceSpec::Serial { port: port.to_string(), baud })
}

/// `/dev/diskN`, `/dev/rdiskN` (macOS) and `/dev/sdX`, `/dev/nvmeX`, `/dev/mmcblkX` (Linux).
fn is_block_device_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else { return false };
    let Some(name) = text.strip_prefix("/dev/") else { return false };
    let numbered = |prefix: &str| name.strip_prefix(prefix).is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
    numbered("disk")
        || numbered("rdisk")
        || name.strip_prefix("sd").is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_lowercase()))
        || name.starts_with("nvme")
        || name.starts_with("mmcblk")
}

// ---------------------------------------------------------------------------
// URLs and block devices
// ---------------------------------------------------------------------------

/// Download a URL, refusing bodies larger than `max_bytes`.
pub fn fetch_url(url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    fetch_url_with_timeout(url, max_bytes, URL_TIMEOUT)
}

/// [`fetch_url`] with an explicit overall timeout.
pub fn fetch_url_with_timeout(url: &str, max_bytes: usize, timeout: Duration) -> Result<Vec<u8>, String> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(10)
        .http_status_as_error(false)
        .build()
        .new_agent();
    let response = agent.get(url).call().map_err(|error| format!("Could not fetch {url}: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Could not fetch {url}: HTTP {}", status.as_u16()));
    }
    let mut body = response.into_body();
    body.with_config()
        .limit(max_bytes as u64)
        .read_to_vec()
        .map_err(|error| match error {
            ureq::Error::BodyExceedsLimit(_) => format!("{url} is larger than the {} MiB limit", max_bytes / (1024 * 1024)),
            other => format!("Could not read {url}: {other}"),
        })
}

/// Read up to `max_bytes` from a block device (or any file) in 1 MiB chunks.
/// Devices report a size of zero, so this reads until end of file or the cap.
pub fn read_block_device(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|error| open_error(path, error))?;
    let mut data = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    while data.len() < max_bytes {
        let want = chunk.len().min(max_bytes - data.len());
        match file.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(read) => data.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(open_error(path, error)),
        }
    }
    Ok(data)
}

fn open_error(path: &Path, error: std::io::Error) -> String {
    match error.kind() {
        ErrorKind::PermissionDenied => format!("needs administrator rights: run theviewer with sudo to read {}", path.display()),
        ErrorKind::NotFound => format!("{} does not exist", path.display()),
        _ => format!("{}: {error}", path.display()),
    }
}

// ---------------------------------------------------------------------------
// Process memory
// ---------------------------------------------------------------------------

/// One mapping from `/proc/<pid>/maps`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub path: String,
}

impl MemoryRegion {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_readable(&self) -> bool {
        self.permissions.starts_with('r')
    }
}

/// Parse the text of `/proc/<pid>/maps`. Lines that do not parse are skipped.
pub fn parse_maps(text: &str) -> Vec<MemoryRegion> {
    text.lines().filter_map(parse_maps_line).collect()
}

fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let permissions = parts.next()?.to_string();
    // offset, device and inode, then an optional path (which may contain spaces).
    let _offset = parts.next()?;
    let _device = parts.next()?;
    let _inode = parts.next()?;
    let path = parts.collect::<Vec<_>>().join(" ");
    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    (end >= start).then_some(MemoryRegion { start, end, permissions, path })
}

/// The memory map of a process (Linux only).
pub fn process_regions(pid: u32) -> Result<Vec<MemoryRegion>, String> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{pid}/maps");
        let text = std::fs::read_to_string(&path).map_err(|error| process_error(pid, error))?;
        Ok(parse_maps(&text))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Err(NOT_LINUX_MESSAGE.to_string())
    }
}

/// Read up to `max_bytes` of one region of a process's memory (Linux only).
pub fn read_process_memory(pid: u32, region: &MemoryRegion, max_bytes: usize) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "linux")]
    {
        use std::io::{Seek, SeekFrom};
        let mut file = File::open(format!("/proc/{pid}/mem")).map_err(|error| process_error(pid, error))?;
        file.seek(SeekFrom::Start(region.start)).map_err(|error| process_error(pid, error))?;
        let len = (region.len() as usize).min(max_bytes);
        let mut data = vec![0u8; len];
        let mut filled = 0;
        while filled < len {
            match file.read(&mut data[filled..]) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(process_error(pid, error)),
            }
        }
        data.truncate(filled);
        Ok(data)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, region, max_bytes);
        Err(NOT_LINUX_MESSAGE.to_string())
    }
}

#[cfg(target_os = "linux")]
fn process_error(pid: u32, error: std::io::Error) -> String {
    match error.kind() {
        ErrorKind::PermissionDenied => {
            format!("needs permission to read process {pid}: run theviewer with sudo, or relax /proc/sys/kernel/yama/ptrace_scope")
        }
        ErrorKind::NotFound => format!("no process with id {pid}"),
        _ => format!("process {pid}: {error}"),
    }
}

// ---------------------------------------------------------------------------
// Serial ports
// ---------------------------------------------------------------------------

/// Names of the serial ports the system knows about.
pub fn list_serial_ports() -> Vec<String> {
    serialport::available_ports()
        .map(|ports| ports.into_iter().map(|port| port.port_name).collect())
        .unwrap_or_default()
}

/// State shared between a capture and its reader thread.
#[derive(Default)]
struct CaptureShared {
    data: Mutex<Vec<u8>>,
    error: Mutex<Option<String>>,
    stop: AtomicBool,
}

/// Bytes arriving on a serial port, collected on a background thread.
pub struct SerialCapture {
    shared: Arc<CaptureShared>,
    reader: Option<JoinHandle<()>>,
    writer: Option<Mutex<Box<dyn serialport::SerialPort>>>,
}

impl SerialCapture {
    /// Open `port` at `baud` (8N1, 100 ms read timeout) and start capturing.
    pub fn start(port: &str, baud: u32) -> Result<SerialCapture, String> {
        let handle = serialport::new(port, baud)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .timeout(Duration::from_millis(100))
            .open()
            .map_err(|error| format!("Could not open {port}: {error}"))?;
        let writer = handle.try_clone().map_err(|error| format!("Could not open {port} for writing: {error}"))?;
        let mut capture = SerialCapture::from_reader(Box::new(handle));
        capture.writer = Some(Mutex::new(writer));
        Ok(capture)
    }

    /// Capture from any reader; used by [`SerialCapture::start`] and by tests.
    pub(crate) fn from_reader(reader: Box<dyn Read + Send>) -> SerialCapture {
        let shared = Arc::new(CaptureShared::default());
        let thread_shared = Arc::clone(&shared);
        let handle = thread::spawn(move || read_until_stopped(reader, &thread_shared));
        SerialCapture { shared, reader: Some(handle), writer: None }
    }

    /// A copy of everything received so far.
    pub fn snapshot(&self) -> Vec<u8> {
        self.shared.data.lock().map(|data| data.clone()).unwrap_or_default()
    }

    /// Bytes received so far.
    pub fn received(&self) -> usize {
        self.shared.data.lock().map(|data| data.len()).unwrap_or(0)
    }

    /// Why the capture stopped, if it stopped on its own.
    pub fn error(&self) -> Option<String> {
        self.shared.error.lock().ok().and_then(|error| error.clone())
    }

    /// Whether the reader thread is still running.
    pub fn is_running(&self) -> bool {
        self.reader.as_ref().is_some_and(|handle| !handle.is_finished())
    }

    /// Write bytes to the port.
    pub fn send(&self, bytes: &[u8]) -> Result<(), String> {
        let writer = self.writer.as_ref().ok_or("This capture has no port to write to")?;
        let mut port = writer.lock().map_err(|_| "The serial port is unavailable".to_string())?;
        port.write_all(bytes).map_err(|error| format!("Could not send: {error}"))?;
        port.flush().map_err(|error| format!("Could not send: {error}"))
    }

    /// Stop capturing and wait for the reader thread.
    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SerialCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_until_stopped(mut reader: Box<dyn Read + Send>, shared: &CaptureShared) {
    let mut buffer = [0u8; 4096];
    while !shared.stop.load(Ordering::Acquire) {
        match reader.read(&mut buffer) {
            Ok(0) => {
                set_error(shared, "The port closed");
                return;
            }
            Ok(read) => {
                let Ok(mut data) = shared.data.lock() else { return };
                let room = SERIAL_CAPTURE_LIMIT.saturating_sub(data.len());
                data.extend_from_slice(&buffer[..read.min(room)]);
                if data.len() >= SERIAL_CAPTURE_LIMIT {
                    drop(data);
                    set_error(shared, "Stopped: the 256 MiB capture limit was reached");
                    return;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::Interrupted | ErrorKind::WouldBlock) => {}
            Err(error) => {
                set_error(shared, &format!("Read failed: {error}"));
                return;
            }
        }
    }
}

fn set_error(shared: &CaptureShared, message: &str) {
    if let Ok(mut error) = shared.error.lock() {
        *error = Some(message.to_string());
    }
}

// ---------------------------------------------------------------------------
// Watch mode
// ---------------------------------------------------------------------------

/// How a watched file changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// Bytes were appended; the old content is unchanged.
    Grew { old_len: usize, new_len: usize },
    Shrank,
    /// The content changed in place (or was replaced entirely).
    Rewritten,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    pub new_len: usize,
}

/// Bytes hashed from each end of the file.
const WATCH_SAMPLE: usize = 4096;

/// Cheap polling for changes to a file on disk.
pub struct FileWatcher {
    path: PathBuf,
    last_len: usize,
    last_modified: Option<SystemTime>,
    /// Hash of the first 4 KiB, used to tell an append from a rewrite.
    last_head_hash: u64,
    /// Hash of the last 4 KiB.
    last_hash_of_tail: u64,
    /// The bytes that ended the file last time, so an append can be confirmed.
    last_tail_bytes: Vec<u8>,
}

impl FileWatcher {
    pub fn new(path: &Path) -> Result<FileWatcher, String> {
        let state = FileState::read(path)?;
        Ok(FileWatcher {
            path: path.to_path_buf(),
            last_len: state.len,
            last_modified: state.modified,
            last_head_hash: state.head_hash,
            last_hash_of_tail: state.tail_hash,
            last_tail_bytes: state.tail,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check the file; `Some` when it changed since the last poll.
    pub fn poll(&mut self) -> Option<Change> {
        let metadata = std::fs::metadata(&self.path).ok()?;
        let len = metadata.len() as usize;
        let modified = metadata.modified().ok();
        if len == self.last_len && modified == self.last_modified {
            // Same size and time: still compare the samples in case the clock is coarse.
            let state = FileState::read(&self.path).ok()?;
            if state.head_hash == self.last_head_hash && state.tail_hash == self.last_hash_of_tail {
                return None;
            }
            return Some(self.update(state, ChangeKind::Rewritten));
        }
        let state = FileState::read(&self.path).ok()?;
        let kind = if state.len < self.last_len {
            ChangeKind::Shrank
        } else if state.len > self.last_len && self.is_append(&state) {
            ChangeKind::Grew { old_len: self.last_len, new_len: state.len }
        } else if state.len == self.last_len && state.head_hash == self.last_head_hash && state.tail_hash == self.last_hash_of_tail {
            // Only the timestamp changed.
            self.last_modified = state.modified;
            return None;
        } else {
            ChangeKind::Rewritten
        };
        Some(self.update(state, kind))
    }

    /// An append keeps the old head and the bytes that used to end the file.
    fn is_append(&self, state: &FileState) -> bool {
        if self.last_len >= WATCH_SAMPLE && state.head_hash != self.last_head_hash {
            return false;
        }
        let old_tail_start = self.last_len - self.last_tail_bytes.len();
        let Ok(now) = read_at(&self.path, old_tail_start, self.last_tail_bytes.len()) else { return false };
        now == self.last_tail_bytes
    }

    fn update(&mut self, state: FileState, kind: ChangeKind) -> Change {
        self.last_len = state.len;
        self.last_modified = state.modified;
        self.last_head_hash = state.head_hash;
        self.last_hash_of_tail = state.tail_hash;
        self.last_tail_bytes = state.tail;
        Change { kind, new_len: state.len }
    }
}

struct FileState {
    len: usize,
    modified: Option<SystemTime>,
    head_hash: u64,
    tail_hash: u64,
    tail: Vec<u8>,
}

impl FileState {
    fn read(path: &Path) -> Result<FileState, String> {
        let metadata = std::fs::metadata(path).map_err(|error| open_error(path, error))?;
        let len = metadata.len() as usize;
        let head = read_at(path, 0, WATCH_SAMPLE.min(len)).map_err(|error| open_error(path, error))?;
        let tail_start = len.saturating_sub(WATCH_SAMPLE);
        let tail = read_at(path, tail_start, len - tail_start).map_err(|error| open_error(path, error))?;
        Ok(FileState { len, modified: metadata.modified().ok(), head_hash: hash(&head), tail_hash: hash(&tail), tail })
    }
}

fn read_at(path: &Path, offset: usize, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut data = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match file.read(&mut data[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    data.truncate(filled);
    Ok(data)
}

/// FNV-1a: fast, and plenty for telling two 4 KiB samples apart.
fn hash(bytes: &[u8]) -> u64 {
    let mut value: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        value ^= byte as u64;
        value = value.wrapping_mul(0x0100_0000_01b3);
    }
    value
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// Block size used when comparing snapshots.
const DELTA_BLOCK: usize = 4096;

/// One stored version of the document.
pub struct Snapshot {
    pub taken_at: SystemTime,
    pub len: usize,
    data: SnapshotData,
}

enum SnapshotData {
    /// The whole content.
    Full(Vec<u8>),
    /// Runs of bytes that differ from the previous snapshot (which may have
    /// been shorter or longer); the result is truncated or extended to `len`.
    Delta(Vec<(usize, Vec<u8>)>),
}

impl SnapshotData {
    fn stored_bytes(&self) -> usize {
        match self {
            SnapshotData::Full(bytes) => bytes.len(),
            SnapshotData::Delta(runs) => runs.iter().map(|(_, bytes)| bytes.len() + std::mem::size_of::<usize>()).sum(),
        }
    }
}

/// A memory-bounded history of a changing document.
pub struct Recording {
    snapshots: Vec<Snapshot>,
    budget_bytes: usize,
    /// The latest content, kept so new snapshots can be diffed cheaply.
    latest: Vec<u8>,
}

impl Default for Recording {
    fn default() -> Self {
        Recording::new(DEFAULT_RECORDING_BUDGET)
    }
}

impl Recording {
    pub fn new(budget_bytes: usize) -> Recording {
        Recording { snapshots: Vec::new(), budget_bytes, latest: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    pub fn taken_at(&self, index: usize) -> Option<SystemTime> {
        self.snapshots.get(index).map(|snapshot| snapshot.taken_at)
    }

    /// Bytes currently held by the history.
    pub fn stored_bytes(&self) -> usize {
        self.snapshots.iter().map(|snapshot| snapshot.data.stored_bytes()).sum()
    }

    /// Record a new version. Returns false (storing nothing) when it is
    /// identical to the last one.
    pub fn record(&mut self, bytes: &[u8]) -> bool {
        if !self.snapshots.is_empty() && bytes == self.latest.as_slice() {
            return false;
        }
        let data = if self.snapshots.is_empty() {
            SnapshotData::Full(bytes.to_vec())
        } else {
            let runs = delta_runs(&self.latest, bytes);
            let delta_size: usize = runs.iter().map(|(_, run)| run.len()).sum();
            if delta_size * 2 > bytes.len() { SnapshotData::Full(bytes.to_vec()) } else { SnapshotData::Delta(runs) }
        };
        self.snapshots.push(Snapshot { taken_at: SystemTime::now(), len: bytes.len(), data });
        self.latest = bytes.to_vec();
        self.evict();
        true
    }

    /// Rebuild the bytes as they were at snapshot `index`.
    pub fn materialise(&self, index: usize) -> Vec<u8> {
        let Some(target) = self.snapshots.get(index) else { return Vec::new() };
        // Walk back to the nearest full snapshot, then replay forwards.
        let base = (0..=index).rev().find(|&i| matches!(self.snapshots[i].data, SnapshotData::Full(_))).unwrap_or(0);
        let mut bytes = match &self.snapshots[base].data {
            SnapshotData::Full(full) => full.clone(),
            SnapshotData::Delta(_) => Vec::new(),
        };
        for snapshot in &self.snapshots[base + 1..=index] {
            apply(&mut bytes, snapshot);
        }
        debug_assert_eq!(bytes.len(), target.len);
        bytes
    }

    /// Ranges `(start, len)` that differ from the previous snapshot.
    pub fn changed_ranges(&self, index: usize) -> Vec<(usize, usize)> {
        if index == 0 || index >= self.snapshots.len() {
            return Vec::new();
        }
        match &self.snapshots[index].data {
            SnapshotData::Delta(runs) => merge_ranges(runs.iter().map(|(offset, run)| (*offset, run.len())).collect()),
            SnapshotData::Full(_) => {
                let previous = self.materialise(index - 1);
                let current = self.materialise(index);
                merge_ranges(delta_runs(&previous, &current).iter().map(|(offset, run)| (*offset, run.len())).collect())
            }
        }
    }

    /// Drop the oldest snapshots while over budget, keeping at least one.
    fn evict(&mut self) {
        while self.snapshots.len() > 1 && self.stored_bytes() > self.budget_bytes {
            // The second snapshot becomes the oldest, so it must be self-contained.
            if matches!(self.snapshots[1].data, SnapshotData::Delta(_)) {
                let rebuilt = self.materialise(1);
                self.snapshots[1].data = SnapshotData::Full(rebuilt);
            }
            self.snapshots.remove(0);
        }
    }
}

fn apply(bytes: &mut Vec<u8>, snapshot: &Snapshot) {
    match &snapshot.data {
        SnapshotData::Full(full) => *bytes = full.clone(),
        SnapshotData::Delta(runs) => {
            bytes.resize(snapshot.len, 0);
            for (offset, run) in runs {
                bytes[*offset..*offset + run.len()].copy_from_slice(run);
            }
        }
    }
}

/// Runs of `new` that differ from `old`, compared in 4 KiB blocks, plus any
/// tail beyond the old length.
fn delta_runs(old: &[u8], new: &[u8]) -> Vec<(usize, Vec<u8>)> {
    let mut runs: Vec<(usize, Vec<u8>)> = Vec::new();
    let common = old.len().min(new.len());
    let mut block = 0;
    while block < common {
        let end = (block + DELTA_BLOCK).min(common);
        if old[block..end] != new[block..end] {
            // Trim the block to the bytes that actually differ.
            let first = (block..end).find(|&i| old[i] != new[i]).unwrap_or(block);
            let last = (block..end).rev().find(|&i| old[i] != new[i]).unwrap_or(first);
            push_run(&mut runs, first, &new[first..=last]);
        }
        block = end;
    }
    if new.len() > common {
        push_run(&mut runs, common, &new[common..]);
    }
    runs
}

/// Append a run, joining it to the previous one when they touch.
fn push_run(runs: &mut Vec<(usize, Vec<u8>)>, offset: usize, bytes: &[u8]) {
    if let Some((last_offset, last)) = runs.last_mut()
        && *last_offset + last.len() == offset
    {
        last.extend_from_slice(bytes);
        return;
    }
    runs.push((offset, bytes.to_vec()));
}

fn merge_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, len) in ranges {
        if let Some((last_start, last_len)) = merged.last_mut()
            && *last_start + *last_len >= start
        {
            *last_len = (*last_len).max(start + len - *last_start);
            continue;
        }
        merged.push((start, len));
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Instant;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("theviewer-sources-{}-{name}", std::process::id()))
    }

    #[test]
    fn parses_every_kind_of_source() {
        assert_eq!(SourceSpec::parse("/tmp/file.bin"), Ok(SourceSpec::File(PathBuf::from("/tmp/file.bin"))));
        assert_eq!(SourceSpec::parse(" https://example.com/a.bin "), Ok(SourceSpec::Url("https://example.com/a.bin".into())));
        assert_eq!(SourceSpec::parse("HTTP://x"), Ok(SourceSpec::Url("HTTP://x".into())));
        assert_eq!(
            SourceSpec::parse("serial:/dev/cu.usbserial-1420@9600"),
            Ok(SourceSpec::Serial { port: "/dev/cu.usbserial-1420".into(), baud: 9600 })
        );
        assert_eq!(SourceSpec::parse("serial:/dev/ttyUSB0"), Ok(SourceSpec::Serial { port: "/dev/ttyUSB0".into(), baud: DEFAULT_BAUD }));
        assert!(SourceSpec::parse("serial:/dev/ttyUSB0@fast").is_err());
        assert!(SourceSpec::parse("serial:").is_err());
        assert_eq!(SourceSpec::parse("/dev/disk2"), Ok(SourceSpec::BlockDevice("/dev/disk2".into())));
        assert_eq!(SourceSpec::parse("/dev/rdisk4"), Ok(SourceSpec::BlockDevice("/dev/rdisk4".into())));
        assert_eq!(SourceSpec::parse("/dev/sda"), Ok(SourceSpec::BlockDevice("/dev/sda".into())));
        assert_eq!(SourceSpec::parse("/dev/null"), Ok(SourceSpec::File("/dev/null".into())));
        assert_eq!(SourceSpec::parse("pid:1234"), Ok(SourceSpec::Process { pid: 1234 }));
        assert!(SourceSpec::parse("pid:abc").is_err());
        assert!(SourceSpec::parse("  ").is_err());
        assert_eq!(SourceSpec::Serial { port: "/dev/x".into(), baud: 9600 }.describe(), "serial port /dev/x at 9600 baud");
    }

    #[test]
    fn parses_proc_maps() {
        let text = "\
55d0c8a00000-55d0c8a21000 r--p 00000000 08:01 1835023                    /usr/bin/cat
55d0c8a21000-55d0c8a3f000 r-xp 00021000 08:01 1835023                    /usr/bin/cat
7ffd1a6e0000-7ffd1a701000 rw-p 00000000 00:00 0                          [stack]
7f00aa000000-7f00aa001000 ---p 00000000 00:00 0
garbage line";
        let regions = parse_maps(text);
        assert_eq!(regions.len(), 4);
        assert_eq!(regions[0].start, 0x55d0_c8a0_0000);
        assert_eq!(regions[0].len(), 0x21000);
        assert_eq!(regions[1].permissions, "r-xp");
        assert_eq!(regions[2].path, "[stack]");
        assert!(regions[3].path.is_empty() && !regions[3].is_readable());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn process_memory_explains_why_it_is_unavailable() {
        let error = process_regions(1).unwrap_err();
        assert!(error.contains("only supported on Linux"), "{error}");
    }

    #[test]
    fn unreachable_url_fails_quickly_with_an_error() {
        let started = Instant::now();
        let result = fetch_url_with_timeout("http://127.0.0.1:9/nothing", 1024, Duration::from_secs(2));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("127.0.0.1"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn block_device_reader_reads_files_and_explains_missing_paths() {
        let path = temp_path("block");
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        assert_eq!(read_block_device(&path, usize::MAX).unwrap(), data);
        assert_eq!(read_block_device(&path, 1000).unwrap(), data[..1000]);
        std::fs::remove_file(&path).ok();
        let error = read_block_device(Path::new("/definitely/not/here"), 10).unwrap_err();
        assert!(error.contains("does not exist"), "{error}");
    }

    #[test]
    fn serial_capture_collects_everything_from_a_reader() {
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i * 7) as u8).collect();
        let capture = SerialCapture::from_reader(Box::new(Cursor::new(payload.clone())));
        let started = Instant::now();
        while capture.is_running() && started.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(capture.snapshot(), payload);
        assert_eq!(capture.received(), payload.len());
        assert_eq!(capture.error().as_deref(), Some("The port closed"));
        assert!(capture.send(b"x").is_err(), "a reader-only capture cannot send");
    }

    #[test]
    fn watcher_tells_growth_rewrites_and_shrinking_apart() {
        let path = temp_path("watch");
        std::fs::write(&path, vec![1u8; 10_000]).unwrap();
        let mut watcher = FileWatcher::new(&path).unwrap();
        assert_eq!(watcher.poll(), None);

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[2u8; 500]).unwrap();
        drop(file);
        assert_eq!(watcher.poll(), Some(Change { kind: ChangeKind::Grew { old_len: 10_000, new_len: 10_500 }, new_len: 10_500 }));
        assert_eq!(watcher.poll(), None);

        // Same length, different content near the end.
        let mut data = vec![1u8; 10_000];
        data.extend_from_slice(&[3u8; 500]);
        std::fs::write(&path, &data).unwrap();
        assert_eq!(watcher.poll().map(|c| c.kind), Some(ChangeKind::Rewritten));

        // Longer but with a changed head: a rewrite, not an append.
        let mut data = vec![9u8; 10_000];
        data.extend_from_slice(&[3u8; 900]);
        std::fs::write(&path, &data).unwrap();
        assert_eq!(watcher.poll().map(|c| c.kind), Some(ChangeKind::Rewritten));

        std::fs::write(&path, vec![1u8; 100]).unwrap();
        assert_eq!(watcher.poll(), Some(Change { kind: ChangeKind::Shrank, new_len: 100 }));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn recording_keeps_versions_and_their_changes() {
        let mut recording = Recording::new(DEFAULT_RECORDING_BUDGET);
        let first: Vec<u8> = (0..20_000u32).map(|i| (i % 253) as u8).collect();
        assert!(recording.record(&first));

        let mut second = first.clone();
        second.extend_from_slice(b"appended tail");
        assert!(recording.record(&second));

        let mut third = second.clone();
        third[9000..9010].copy_from_slice(b"0123456789");
        assert!(recording.record(&third));
        assert!(!recording.record(&third), "identical versions are not stored");

        assert_eq!(recording.len(), 3);
        assert_eq!(recording.materialise(0), first);
        assert_eq!(recording.materialise(1), second);
        assert_eq!(recording.materialise(2), third);
        assert_eq!(recording.changed_ranges(1), vec![(20_000, 13)]);
        assert_eq!(recording.changed_ranges(2), vec![(9000, 10)]);
        assert!(recording.changed_ranges(0).is_empty());
        assert!(recording.stored_bytes() < first.len() + 1000, "later versions are stored as deltas");
        assert!(recording.taken_at(2).is_some());
    }

    #[test]
    fn recording_evicts_oldest_versions_within_its_budget() {
        // One full 12 kB version plus 2.5 kB deltas: only a couple fit.
        let mut recording = Recording::new(16_000);
        let mut versions = Vec::new();
        let mut bytes: Vec<u8> = (0..12_000u32).map(|i| (i % 249) as u8).collect();
        for round in 0..6u8 {
            // Change a few kilobytes each time so deltas are substantial.
            let start = round as usize * 1500;
            for byte in &mut bytes[start..start + 2500] {
                *byte = byte.wrapping_add(round + 1);
            }
            recording.record(&bytes);
            versions.push(bytes.clone());
        }
        assert!(recording.len() < 6, "old versions were evicted");
        assert!(recording.stored_bytes() <= 16_000 || recording.len() == 1);
        let kept = recording.len();
        for index in 0..kept {
            assert_eq!(recording.materialise(index), versions[versions.len() - kept + index]);
        }
    }
}
