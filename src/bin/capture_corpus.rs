//! A developer tool: fetch Wireshark's sample captures into a local cache and
//! run our packet code (and tshark, when installed) over them.
//!
//! Usage: `cargo run --release --bin capture_corpus -- <command>`
//!
//! * `fetch` downloads the captures listed on <https://wiki.wireshark.org/SampleCaptures>
//!   into `~/.cache/theviewer/corpus/` (or `$THEVIEWER_CORPUS_DIR`), skipping
//!   ones already there, and unpacks compressed ones.
//! * `run [--no-tshark] [--only TEXT] [--files N]` reads every capture with our
//!   readers and dissectors, compares with tshark, and writes reports to the
//!   cache's `report/` directory.
//!
//! The captures have no licence statement, so they stay in the cache and are
//! never copied into the repository.

use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

use theviewer::corpus::report::CorpusReport;
use theviewer::corpus::{self, CorpusPaths, fetch, run};
use theviewer::packets::tshark;

const USAGE: &str = "usage: capture_corpus fetch | run [--no-tshark] [--only TEXT] [--files N]";

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    let paths = match corpus::default_root() {
        Ok(root) => CorpusPaths::new(root),
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    };
    let outcome = match command.as_str() {
        "fetch" => fetch::fetch(&paths, |line| println!("{line}")).map(|manifest| {
            let kept = manifest.downloads.iter().filter(|download| download.status == "ok").count();
            let captures: usize = manifest.downloads.iter().map(|download| download.captures.len()).sum();
            println!("{kept} of {} downloads in {}; {captures} captures unpacked", manifest.downloads.len(), paths.root.display());
        }),
        "run" => run_corpus(&paths, &args.collect::<Vec<_>>()),
        _ => Err(USAGE.to_string()),
    };
    if let Err(message) = outcome {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

fn run_corpus(paths: &CorpusPaths, options: &[String]) -> Result<(), String> {
    let use_tshark = !options.iter().any(|option| option == "--no-tshark");
    let value_of = |name: &str| options.iter().position(|option| option == name).and_then(|at| options.get(at + 1)).cloned();
    let only = value_of("--only");
    let most_files = value_of("--files").and_then(|text| text.parse::<usize>().ok()).unwrap_or(usize::MAX);

    let mut files: Vec<PathBuf> = std::fs::read_dir(&paths.captures)
        .map_err(|error| format!("{}: {error}; run `capture_corpus fetch` first", paths.captures.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .filter(|path| {
            let mut head = Vec::new();
            if let Ok(file) = std::fs::File::open(path) {
                let _ = file.take(16).read_to_end(&mut head);
            }
            fetch::looks_like_capture(&path.file_name().unwrap_or_default().to_string_lossy(), &head)
        })
        .filter(|path| only.as_deref().is_none_or(|text| path.to_string_lossy().contains(text)))
        .collect();
    files.sort();
    files.truncate(most_files);

    let tshark_path = if use_tshark { tshark::find_tshark(None) } else { None };
    match &tshark_path {
        Some(path) => println!("comparing with {}", path.display()),
        None => println!("tshark not used; only our own code runs"),
    }
    run::install_panic_recorder();
    let registry = theviewer::app::build_registry();
    let mut report = CorpusReport { tshark_used: tshark_path.is_some(), ..CorpusReport::default() };
    let started = Instant::now();
    for (number, path) in files.iter().enumerate() {
        let result = run::run_file(path, &registry, tshark_path.as_deref());
        let failures = if result.failures.is_empty() { String::new() } else { format!(", {} failures", result.failures.len()) };
        println!(
            "[{}/{}] {} — {} packets{failures} ({:.1} s)",
            number + 1,
            files.len(),
            result.file,
            result.opened.as_ref().map_or_else(|| "?".to_string(), |opened| opened.as_ref().map_or_else(|error| format!("not opened: {error};"), |packets| packets.to_string())),
            result.elapsed.as_secs_f64()
        );
        report.add(result);
    }
    report.write(&paths.reports)?;
    println!("{} files in {:.0} s; reports in {}", files.len(), started.elapsed().as_secs_f64(), paths.reports.display());
    Ok(())
}
