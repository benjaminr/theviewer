//! Downloading the sample captures listed on Wireshark's wiki into the
//! corpus cache, politely and resumably, with a manifest of what came from
//! where.

use std::collections::BTreeSet;
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use super::archive;
use super::{CorpusPaths, sha256_hex};

/// The page that lists the sample captures.
pub const SAMPLE_CAPTURES_PAGE: &str = "https://wiki.wireshark.org/SampleCaptures";
const SITE: &str = "https://wiki.wireshark.org";
/// The wiki serves its pages to browsers; a plain client is turned away.
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
/// Most bytes downloaded for one file.
pub const MAX_DOWNLOAD_BYTES: usize = 50 * 1024 * 1024;
/// Most bytes downloaded for the whole corpus; later files are skipped and
/// listed in the manifest.
pub const MAX_TOTAL_DOWNLOAD_BYTES: usize = 1536 * 1024 * 1024;
/// Status of a file left out because the corpus reached its size cap; such
/// files are tried again on the next fetch.
const SKIPPED_FOR_TOTAL: &str = "skipped: the corpus reached its total size cap";
/// Most bytes one capture may unpack to.
pub const MAX_UNPACKED_BYTES: usize = 200 * 1024 * 1024;
const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
/// Pause between downloads, so the wiki is not hammered.
const DELAY_BETWEEN_DOWNLOADS: Duration = Duration::from_millis(1500);
/// The wiki answers "too many requests" when asked too often; wait this
/// long before the first retry, doubling each time.
const FIRST_BACK_OFF: Duration = Duration::from_secs(30);
const MOST_RETRIES: u32 = 5;
const TOO_MANY_REQUESTS: &str = "HTTP 429";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Extensions of capture files, after any compression suffix is removed.
const CAPTURE_EXTENSIONS: [&str; 10] = ["pcap", "pcapng", "cap", "ntar", "erf", "snoop", "trc", "trace", "dmp", "pkt"];
/// Compression and archive suffixes worth downloading.
const PACKED_EXTENSIONS: [&str; 7] = ["gz", "tgz", "zip", "bz2", "xz", "7z", "tar"];

/// Every download and what it unpacked to.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub downloads: Vec<Download>,
}

/// One file fetched from the wiki.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Download {
    pub url: String,
    /// File name in the downloads directory.
    pub file: String,
    pub size: usize,
    pub sha256: String,
    /// "ok", or why the file was not kept.
    pub status: String,
    /// The captures unpacked from it into the captures directory.
    pub captures: Vec<CaptureFile>,
    /// What could not be unpacked.
    pub problems: Vec<String>,
}

/// One capture in the captures directory.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CaptureFile {
    pub file: String,
    pub size: usize,
    pub sha256: String,
}

impl Manifest {
    pub fn load(path: &Path) -> Manifest {
        std::fs::read_to_string(path).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|error| error.to_string())?;
        std::fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
    }

    fn entry(&self, url: &str) -> Option<&Download> {
        self.downloads.iter().find(|download| download.url == url)
    }
}

/// The capture links on the sample captures page: the wiki's own uploads
/// whose names end in a capture extension, a compression suffix or both,
/// as absolute URLs, each once, in page order.
pub fn capture_links(html: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut links = Vec::new();
    for piece in html.split("href=\"").skip(1) {
        let Some(target) = piece.split('"').next() else { continue };
        let target = target.replace("&amp;", "&");
        let absolute = if target.starts_with('/') { format!("{SITE}{target}") } else { target };
        let Some(path) = absolute.strip_prefix(SITE) else { continue };
        if !path.starts_with("/uploads/") || path.contains('?') || path.contains('#') {
            continue;
        }
        if is_capture_name(&file_name_of(&absolute)) && seen.insert(absolute.clone()) {
            links.push(absolute);
        }
    }
    links
}

/// Whether a file name looks like a capture, possibly compressed or
/// archived.
pub fn is_capture_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let mut parts: Vec<&str> = lower.rsplit('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let last = parts.remove(0);
    CAPTURE_EXTENSIONS.contains(&last) || PACKED_EXTENSIONS.contains(&last)
}

/// Whether an unpacked file is worth keeping: a capture by its name, or by
/// a pcap or pcapng header. Archives also hold notes, keys and scripts.
pub fn looks_like_capture(name: &str, bytes: &[u8]) -> bool {
    is_capture_name(name) || crate::packets::sources::capture_format(bytes).is_some()
}

/// The last part of a URL's path, with percent escapes decoded and anything
/// unsafe in a file name replaced.
pub fn file_name_of(url: &str) -> String {
    let last = url.rsplit('/').next().unwrap_or_default();
    let decoded = percent_decode(last);
    let safe: String = decoded.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
    if safe.is_empty() { "capture".to_string() } else { safe }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && let Some(byte) = text.get(at + 1..at + 3).and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A local name for `url` not already used by another download.
fn unique_name(manifest: &Manifest, url: &str) -> String {
    let name = file_name_of(url);
    if manifest.downloads.iter().any(|download| download.file == name && download.url != url) {
        let digest = sha256_hex(url.as_bytes());
        return format!("{}-{name}", &digest[..8]);
    }
    name
}

fn get(url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let agent = ureq::Agent::config_builder().timeout_global(Some(DOWNLOAD_TIMEOUT)).max_redirects(10).http_status_as_error(false).build().new_agent();
    let response = agent.get(url).header("User-Agent", USER_AGENT).call().map_err(|error| format!("could not fetch: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status.as_u16()));
    }
    response.into_body().with_config().limit(max_bytes as u64).read_to_vec().map_err(|error| match error {
        ureq::Error::BodyExceedsLimit(_) => format!("larger than {} MiB, skipped", max_bytes / (1024 * 1024)),
        other => format!("could not read: {other}"),
    })
}

/// [`get`], waiting and trying again while the wiki says it is asked too often.
fn get_with_back_off(url: &str, log: &mut impl FnMut(&str)) -> Result<Vec<u8>, String> {
    let mut wait = FIRST_BACK_OFF;
    for _ in 0..MOST_RETRIES {
        match get(url, MAX_DOWNLOAD_BYTES) {
            Err(problem) if problem == TOO_MANY_REQUESTS => {
                log(&format!("  asked too often; waiting {} s", wait.as_secs()));
                thread::sleep(wait);
                wait *= 2;
            }
            other => return other,
        }
    }
    get(url, MAX_DOWNLOAD_BYTES)
}

/// Download every capture the page lists that is not in the cache yet, and
/// unpack each into the captures directory. Progress goes to `log`.
pub fn fetch(paths: &CorpusPaths, mut log: impl FnMut(&str)) -> Result<Manifest, String> {
    for dir in [&paths.downloads, &paths.captures] {
        std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    }
    let page = get(SAMPLE_CAPTURES_PAGE, MAX_PAGE_BYTES).map_err(|error| format!("{SAMPLE_CAPTURES_PAGE}: {error}"))?;
    let links = capture_links(&String::from_utf8_lossy(&page));
    log(&format!("{} capture links on {SAMPLE_CAPTURES_PAGE}", links.len()));
    let mut manifest = Manifest::load(&paths.manifest);
    for (number, url) in links.iter().enumerate() {
        if let Some(done) = manifest.entry(url)
            && (done.status != "ok" || paths.downloads.join(&done.file).is_file())
            && !done.status.starts_with("could not fetch")
            && done.status != TOO_MANY_REQUESTS
            && done.status != SKIPPED_FOR_TOTAL
        {
            continue;
        }
        let downloaded: usize = manifest.downloads.iter().filter(|download| download.status == "ok").map(|download| download.size).sum();
        if downloaded >= MAX_TOTAL_DOWNLOAD_BYTES {
            manifest.downloads.retain(|known| known.url != *url);
            manifest.downloads.push(Download { url: url.clone(), file: file_name_of(url), status: SKIPPED_FOR_TOTAL.to_string(), ..Download::default() });
            continue;
        }
        let file = unique_name(&manifest, url);
        log(&format!("[{}/{}] {file}", number + 1, links.len()));
        let mut download = Download { url: url.clone(), file: file.clone(), ..Download::default() };
        match get_with_back_off(url, &mut log) {
            Ok(bytes) => {
                download.size = bytes.len();
                download.sha256 = sha256_hex(&bytes);
                download.status = "ok".to_string();
                std::fs::write(paths.downloads.join(&file), &bytes).map_err(|error| format!("{file}: {error}"))?;
                let unpacked = archive::unpack(&file, bytes, MAX_UNPACKED_BYTES);
                download.problems = unpacked.problems;
                for (name, data) in unpacked.files {
                    if !looks_like_capture(&name, &data) {
                        download.problems.push(format!("{name}: not a capture, left out"));
                        continue;
                    }
                    let capture = CaptureFile { file: name.clone(), size: data.len(), sha256: sha256_hex(&data) };
                    std::fs::write(paths.captures.join(&name), &data).map_err(|error| format!("{name}: {error}"))?;
                    download.captures.push(capture);
                }
            }
            Err(problem) => {
                log(&format!("  {problem}"));
                download.status = problem;
            }
        }
        manifest.downloads.retain(|known| known.url != *url);
        manifest.downloads.push(download);
        manifest.save(&paths.manifest)?;
        thread::sleep(DELAY_BETWEEN_DOWNLOADS);
    }
    manifest.save(&paths.manifest)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_links_are_the_sites_own_uploads_once_each() {
        let html = r#"
            <a href="/uploads/__moin_import__/attachments/SampleCaptures/dhcp.pcap">dhcp</a>
            <a href="/uploads/abc/arp%20storm.pcapng.gz">storm</a>
            <a href="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dhcp.pcap">again</a>
            <a href="/uploads/abc/readme.txt">notes</a>
            <a href="https://example.com/uploads/elsewhere.pcap">elsewhere</a>
            <a href="/SampleCaptures?action=edit">edit</a>
            <a href="/uploads/x/bundle.zip">bundle</a>
            <a href="/uploads/x/TRACE.CAP">trace</a>
        "#;
        assert_eq!(
            capture_links(html),
            vec![
                "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dhcp.pcap",
                "https://wiki.wireshark.org/uploads/abc/arp%20storm.pcapng.gz",
                "https://wiki.wireshark.org/uploads/x/bundle.zip",
                "https://wiki.wireshark.org/uploads/x/TRACE.CAP",
            ]
        );
    }

    #[test]
    fn notes_and_keys_unpacked_from_an_archive_are_not_taken_for_captures() {
        assert!(looks_like_capture("trace.pcapng", b""));
        assert!(looks_like_capture("capture.dat", &[0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0]));
        assert!(!looks_like_capture("README.txt", b"About these captures"));
        assert!(!looks_like_capture("acme.keytab", &[5, 2, 0, 0]));
    }

    #[test]
    fn file_names_are_decoded_and_made_safe() {
        assert_eq!(file_name_of("https://wiki.wireshark.org/uploads/abc/arp%20storm.pcapng.gz"), "arp_storm.pcapng.gz");
        assert_eq!(file_name_of("https://wiki.wireshark.org/uploads/abc/a%2F..%2Fb.pcap"), "a_.._b.pcap");
    }

    #[test]
    fn a_name_taken_by_another_download_gets_a_prefix() {
        let manifest = Manifest { downloads: vec![Download { url: "https://wiki.wireshark.org/uploads/a/x.pcap".into(), file: "x.pcap".into(), ..Download::default() }] };
        assert_eq!(unique_name(&manifest, "https://wiki.wireshark.org/uploads/a/x.pcap"), "x.pcap");
        let other = unique_name(&manifest, "https://wiki.wireshark.org/uploads/b/x.pcap");
        assert!(other.ends_with("-x.pcap") && other.len() == "x.pcap".len() + 9, "{other}");
    }

    #[test]
    fn a_manifest_survives_saving_and_loading() {
        let path = std::env::temp_dir().join(format!("theviewer-corpus-manifest-{}.json", std::process::id()));
        let manifest = Manifest {
            downloads: vec![Download {
                url: "u".into(),
                file: "f".into(),
                size: 3,
                sha256: "s".into(),
                status: "ok".into(),
                captures: vec![CaptureFile { file: "f".into(), size: 3, sha256: "s".into() }],
                problems: Vec::new(),
            }],
        };
        manifest.save(&path).unwrap();
        assert_eq!(Manifest::load(&path), manifest);
        std::fs::remove_file(&path).ok();
        assert_eq!(Manifest::load(&path), Manifest::default(), "a missing manifest is an empty one");
    }
}
