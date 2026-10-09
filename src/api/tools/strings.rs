//! `strings.find`: the Strings tool's search of a span for runs of text in
//! the encodings chosen, run as a job.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::analysis_stats::{self, FoundStrings};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::Workspace;
use crate::api::{ApiError, Caller};
use crate::strings::Encoding;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[method!(
    "strings.find",
    Job,
    caller find,
    FindParams,
    JobStartedResult,
    "Start the Strings tool's search of a span (at most 64 MiB) for runs of text at least min_chars long in the encodings chosen, as a job: the strings found (at most 200000), each with its offset, length, encoding, text and what it looks like (a URL, a path, a key…), are job.finished's result, and in the window they fill the Strings tab."
)];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("strings.find", json!({"start": 0, "min_chars": 6, "encodings": ["ascii", "utf16le"]}))]
}

/// Fewest characters a string may be asked to have.
pub const FEWEST_CHARS: usize = 2;
/// Most characters a string may be asked to have at least.
pub const MOST_MIN_CHARS: usize = 256;
/// Characters a string has at least when not asked.
pub const DEFAULT_MIN_CHARS: usize = 6;

/// A text encoding the Strings tool looks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16le,
    Utf16be,
}

impl StringEncoding {
    /// The encodings looked for when none are named: all but UTF-16BE, as the tool starts.
    pub const DEFAULT: [StringEncoding; 3] = [StringEncoding::Ascii, StringEncoding::Utf8, StringEncoding::Utf16le];

    pub fn of(encoding: Encoding) -> Self {
        match encoding {
            Encoding::Ascii => StringEncoding::Ascii,
            Encoding::Utf8 => StringEncoding::Utf8,
            Encoding::Utf16Le => StringEncoding::Utf16le,
            Encoding::Utf16Be => StringEncoding::Utf16be,
        }
    }

    pub fn encoding(self) -> Encoding {
        match self {
            StringEncoding::Ascii => Encoding::Ascii,
            StringEncoding::Utf8 => Encoding::Utf8,
            StringEncoding::Utf16le => Encoding::Utf16Le,
            StringEncoding::Utf16be => Encoding::Utf16Be,
        }
    }
}

/// Parameters of `strings.find`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset searched (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes searched, at most 64 MiB; to the end of the document (or 64 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Fewest characters in a string, 2 to 256 (6 by default).
    #[serde(default)]
    pub min_chars: Option<usize>,
    /// The encodings looked for (ascii, utf8 and utf16le by default).
    #[serde(default)]
    pub encodings: Option<Vec<StringEncoding>>,
}

/// One string found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StringFound {
    /// Document offset of its first byte.
    pub offset: u64,
    /// Bytes it takes up.
    pub len: u64,
    pub encoding: StringEncoding,
    pub text: String,
    /// What it looks like, such as "URL" or "path", when it stands out.
    pub tag: Option<String>,
}

/// What `strings.find`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StringsFound {
    /// First offset searched.
    pub start: u64,
    /// Bytes searched.
    pub len: u64,
    /// The strings, in document order.
    pub strings: Vec<StringFound>,
    /// Whether the search stopped at the limit of 200000 strings.
    pub truncated: bool,
}

impl StringsFound {
    /// The tool's result as an API caller collects it.
    pub fn of(found: &FoundStrings) -> Self {
        StringsFound {
            start: found.start as u64,
            len: found.len as u64,
            strings: found
                .strings
                .iter()
                .map(|string| StringFound {
                    offset: string.offset as u64,
                    len: string.len_bytes as u64,
                    encoding: StringEncoding::of(string.encoding),
                    text: string.text.clone(),
                    tag: crate::strings::classify(&string.text).map(str::to_string),
                })
                .collect(),
            truncated: found.strings.len() >= analysis_stats::MAX_STRINGS,
        }
    }
}

/// `strings.find`: read the span now and search it on a thread.
pub fn find(workspace: &mut dyn Workspace, caller: &Caller, params: FindParams) -> Result<JobStartedResult, ApiError> {
    let min_chars = params.min_chars.unwrap_or(DEFAULT_MIN_CHARS);
    if !(FEWEST_CHARS..=MOST_MIN_CHARS).contains(&min_chars) {
        return Err(ApiError::invalid_params(format!("min_chars of {min_chars} is outside {FEWEST_CHARS} to {MOST_MIN_CHARS}")));
    }
    let encodings: Vec<Encoding> = params.encodings.unwrap_or_else(|| StringEncoding::DEFAULT.to_vec()).into_iter().map(StringEncoding::encoding).collect();
    if encodings.is_empty() {
        return Err(ApiError::invalid_params("name at least one encoding to look for, such as \"ascii\""));
    }
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, analysis_stats::SCAN_LIMIT, "the span searched")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(analysis_stats::await_strings);
    let start = span.start;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("strings", "Strings"),
        &span,
        deliver,
        move |_| analysis_stats::find_strings(&bytes, start, min_chars, &encodings),
        |found| Summary::of(format!("{} strings", found.strings.len()), StringsFound::of(found)),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    fn text_among_zeros() -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        bytes.extend(b"https://example.com/index.html");
        bytes.extend([0u8; 16]);
        bytes.extend("wide".encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend([0u8; 16]);
        bytes
    }

    #[test]
    fn finding_strings_lists_each_with_its_offset_encoding_and_kind() {
        let mut workspace = workspace_with("a.bin", &text_among_zeros());
        let status = run_job(&mut workspace, "strings.find", json!({"min_chars": 4, "encodings": ["ascii", "utf16le"]}));
        assert_eq!(status["state"], "finished", "{status}");
        let strings = status["result"]["strings"].as_array().unwrap();
        assert_eq!(strings[0]["offset"], 32);
        assert_eq!(strings[0]["text"], "https://example.com/index.html");
        assert_eq!(strings[0]["tag"], "URL");
        assert!(strings.iter().any(|string| string["text"] == "wide" && string["encoding"] == "utf16le"), "{strings:?}");
        let ascii_only = run_job(&mut workspace, "strings.find", json!({"min_chars": 4, "encodings": ["ascii"]}));
        assert!(ascii_only["result"]["strings"].as_array().unwrap().iter().all(|string| string["encoding"] == "ascii"));
    }

    #[test]
    fn a_search_with_too_few_characters_or_no_encodings_is_refused() {
        let mut workspace = workspace_with("a.bin", &text_among_zeros());
        assert_eq!(call(&mut workspace, "strings.find", json!({"min_chars": 1})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "strings.find", json!({"encodings": []})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "strings.find", json!({"encodings": ["ebcdic"]})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "strings.find", json!({"start": 1000})).unwrap_err().code, ErrorCode::OutOfRange);
    }
}
