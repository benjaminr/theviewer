//! `firmware.*`: the Firmware tool's analyses of headerless code: which
//! processor it is for, where the image is loaded, and ARM Cortex-M vector
//! tables.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller};
use crate::base_address::{BaseSearchOptions, BaseSearchReport, ByteOrder, PointerWidth};
use crate::cortex_m::VectorTable;
use crate::cpu_detect::CpuReport;
use crate::panel_firmware;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("firmware.identify", Job, caller identify, FirmwareSpanParams, JobStartedResult, "Start identifying the processor of a span of headerless code (at most 64 MiB) as a job, disassembling samples as every supported architecture and ranking them by typical instructions, idioms and branch targets: the ranking is job.finished's result, and in the window it fills Firmware (analysis.processor is the quick read)."),
    method!("firmware.find_load_address", Job, caller find_load_address, LoadAddressParams, JobStartedResult, "Start a search for the address a firmware image is loaded at (the address of offset 0, over the document's first 64 MiB) as a job: the bases that make most stored pointers land on the start of a string, as rbasefind does, are job.finished's result, and in the window they fill Firmware."),
    method!("firmware.vector_tables", Job, caller vector_tables, FirmwareSpanParams, JobStartedResult, "Start a search of a span (the whole document by default, at most 64 MiB) for ARM Cortex-M vector tables as a job: each table's stack pointer, handlers and the flash base they imply are job.finished's result, and in the window they fill Firmware."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("firmware.identify", json!({"start": 0})),
        ("firmware.find_load_address", json!({"width": 32, "byte_order": "little", "step": 4096, "min_string_len": 8})),
        ("firmware.vector_tables", json!({})),
    ]
}

/// Most bytes any of the analyses read.
pub const FIRMWARE_LIMIT: usize = 64 * 1024 * 1024;

/// A span of the document.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirmwareSpanParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset read (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes read, at most 64 MiB; to the end of the document (or 64 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// Byte order of stored pointers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PointerOrder {
    Little,
    Big,
}

impl PointerOrder {
    pub fn of(order: ByteOrder) -> Self {
        match order {
            ByteOrder::Little => PointerOrder::Little,
            ByteOrder::Big => PointerOrder::Big,
        }
    }

    fn byte_order(self) -> ByteOrder {
        match self {
            PointerOrder::Little => ByteOrder::Little,
            PointerOrder::Big => ByteOrder::Big,
        }
    }
}

/// Parameters of `firmware.find_load_address`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LoadAddressParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// Bits in a stored pointer: 32 (the default) or 64.
    #[serde(default)]
    pub width: Option<u32>,
    /// Byte order of the pointers; both are tried when omitted.
    #[serde(default)]
    pub byte_order: Option<PointerOrder>,
    /// Candidate bases are multiples of this, at least 0x10 (0x1000 by default).
    #[serde(default)]
    pub step: Option<u64>,
    /// Shortest string counted as a pointer target, 4 to 64 (10 by default).
    #[serde(default)]
    pub min_string_len: Option<usize>,
}

impl LoadAddressParams {
    /// The search's options, or why they cannot be.
    fn options(&self) -> Result<BaseSearchOptions, ApiError> {
        let defaults = BaseSearchOptions::default();
        let width = match self.width.unwrap_or(32) {
            32 => PointerWidth::Bits32,
            64 => PointerWidth::Bits64,
            other => return Err(ApiError::invalid_params(format!("pointers of {other} bits are not searched for; use 32 or 64"))),
        };
        let step = self.step.unwrap_or(defaults.step);
        if !(crate::base_address::MIN_STEP..=MOST_STEP).contains(&step) {
            return Err(ApiError::invalid_params(format!("a step of {step:#x} is outside {:#x} to {MOST_STEP:#x}", crate::base_address::MIN_STEP)));
        }
        let min_string_len = self.min_string_len.unwrap_or(defaults.min_string_len);
        if !MIN_STRING_LENS.contains(&min_string_len) {
            return Err(ApiError::invalid_params(format!("strings of at least {min_string_len} characters is outside {} to {}", MIN_STRING_LENS.start(), MIN_STRING_LENS.end())));
        }
        Ok(BaseSearchOptions { width, byte_order: self.byte_order.map(PointerOrder::byte_order), step, min_string_len, ..defaults })
    }
}

/// Largest step between candidate bases.
pub const MOST_STEP: u64 = 0x100_0000;
/// Shortest strings that may be asked for.
pub const MIN_STRING_LENS: std::ops::RangeInclusive<usize> = 4..=64;

/// One architecture's score.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessorScore {
    /// Such as "ARM Thumb" or "x86-64".
    pub architecture: String,
    /// 0 to 1.
    pub confidence: f32,
    pub reason: String,
    /// Document offset of the sample that looked most like it.
    pub best_window_offset: u64,
}

/// What `firmware.identify`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessorIdentified {
    pub summary: String,
    /// Whether no architecture is convincing.
    pub looks_like_data: bool,
    /// Samples and bytes disassembled per architecture.
    pub windows: usize,
    pub sampled_bytes: u64,
    /// Every architecture, best first.
    pub candidates: Vec<ProcessorScore>,
}

impl ProcessorIdentified {
    fn of(report: &CpuReport) -> Self {
        ProcessorIdentified {
            summary: report.summary.clone(),
            looks_like_data: report.looks_like_data,
            windows: report.windows,
            sampled_bytes: report.sampled_bytes as u64,
            candidates: report
                .candidates
                .iter()
                .map(|candidate| ProcessorScore { architecture: candidate.arch.label().to_string(), confidence: candidate.confidence, reason: candidate.reason.clone(), best_window_offset: candidate.best_window_offset as u64 })
                .collect(),
        }
    }
}

/// A stored pointer and the string it lands on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PointerToString {
    pub pointer_offset: u64,
    pub string_offset: u64,
}

/// A possible load address.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LoadAddress {
    /// The address of offset 0.
    pub base: u64,
    pub width: u32,
    pub byte_order: PointerOrder,
    /// Distinct strings pointed at, and the pointers that do.
    pub matched_strings: usize,
    pub references: usize,
    pub examples: Vec<PointerToString>,
}

/// What `firmware.find_load_address`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LoadAddresses {
    pub summary: String,
    pub strings_considered: usize,
    pub pointers_considered: usize,
    /// Whether a limit cut the search short.
    pub truncated: bool,
    /// Best first.
    pub candidates: Vec<LoadAddress>,
}

impl LoadAddresses {
    fn of(report: &BaseSearchReport) -> Self {
        LoadAddresses {
            summary: report.summary.clone(),
            strings_considered: report.strings_considered,
            pointers_considered: report.pointers_considered,
            truncated: report.truncated,
            candidates: report
                .candidates
                .iter()
                .map(|candidate| LoadAddress {
                    base: candidate.base,
                    width: candidate.width.bytes() as u32 * 8,
                    byte_order: PointerOrder::of(candidate.byte_order),
                    matched_strings: candidate.matched_strings,
                    references: candidate.references,
                    examples: candidate.examples.iter().map(|example| PointerToString { pointer_offset: example.pointer_offset as u64, string_offset: example.string_offset as u64 }).collect(),
                })
                .collect(),
        }
    }
}

/// One entry of a vector table.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorFound {
    /// Such as "Reset" or "IRQ 3".
    pub name: String,
    pub offset: u64,
    pub value: u32,
}

/// A Cortex-M vector table.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorTableFound {
    pub offset: u64,
    pub initial_stack_pointer: u32,
    pub reset_handler: u32,
    /// The address of offset 0 the handlers imply.
    pub inferred_flash_base: u64,
    /// Whether every handler falls inside the document under that base.
    pub base_consistent: bool,
    pub valid_vectors: usize,
    pub confidence: f32,
    pub entries: Vec<VectorFound>,
}

/// What `firmware.vector_tables`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorTables {
    pub tables: Vec<VectorTableFound>,
}

impl VectorTables {
    fn of(tables: &[VectorTable]) -> Self {
        VectorTables {
            tables: tables
                .iter()
                .map(|table| VectorTableFound {
                    offset: table.offset as u64,
                    initial_stack_pointer: table.initial_stack_pointer,
                    reset_handler: table.reset_handler,
                    inferred_flash_base: table.inferred_flash_base,
                    base_consistent: table.base_consistent,
                    valid_vectors: table.valid_vectors,
                    confidence: table.confidence,
                    entries: table.entries.iter().map(|entry| VectorFound { name: entry.name.clone(), offset: entry.offset as u64, value: entry.value }).collect(),
                })
                .collect(),
        }
    }
}

/// `firmware.identify`: read the span now and disassemble samples on a thread.
pub fn identify(workspace: &mut dyn Workspace, caller: &Caller, params: FirmwareSpanParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, FIRMWARE_LIMIT, "the span")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_firmware::await_processor);
    let start = span.start;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("processor", "Identify processor"),
        &span,
        deliver,
        move |_| crate::cpu_detect::identify_architecture(&bytes, start),
        |report| Summary::of(report.summary.clone(), ProcessorIdentified::of(report)),
    ))
}

/// `firmware.find_load_address`: read the document's start now and search on a thread.
pub fn find_load_address(workspace: &mut dyn Workspace, caller: &Caller, params: LoadAddressParams) -> Result<JobStartedResult, ApiError> {
    let options = params.options()?;
    let span = tool_jobs::span(workspace, params.doc.as_deref(), 0, None, FIRMWARE_LIMIT, "the image")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_firmware::await_load_address);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("load-address", "Find load address"),
        &span,
        deliver,
        move |_| crate::base_address::find_base_address(&bytes, &options),
        |report| Summary::of(report.summary.clone(), LoadAddresses::of(report)),
    ))
}

/// `firmware.vector_tables`: read the span now and search it on a thread.
pub fn vector_tables(workspace: &mut dyn Workspace, caller: &Caller, params: FirmwareSpanParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, FIRMWARE_LIMIT, "the span")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let document_len = workspace::info(workspace, &span.doc)?.len as usize;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_firmware::await_vector_tables);
    let start = span.start;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("vector-tables", "Cortex-M vector tables"),
        &span,
        deliver,
        move |_| crate::cortex_m::find_vector_tables(&bytes, start, document_len),
        |tables| Summary::of(format!("{} tables", tables.len()), VectorTables::of(tables)),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn a_cortex_m_image_is_thumb_loaded_at_its_flash_base_with_its_vector_table() {
        let mut workspace = workspace_with("firmware.bin", &crate::panel_firmware::cortex_m_image());
        let identified = run_job(&mut workspace, "firmware.identify", json!({}));
        assert_eq!(identified["state"], "finished", "{identified}");
        assert_eq!(identified["result"]["candidates"][0]["architecture"], crate::disasm::Arch::Thumb.label());
        let based = run_job(&mut workspace, "firmware.find_load_address", json!({"byte_order": "little"}));
        assert_eq!(based["result"]["candidates"][0]["base"], 0x0800_0000u64, "{based}");
        let tables = run_job(&mut workspace, "firmware.vector_tables", json!({}));
        assert_eq!(tables["result"]["tables"][0]["initial_stack_pointer"], 0x2000_2000u32);
    }

    #[test]
    fn a_load_address_search_with_odd_options_is_refused() {
        let mut workspace = workspace_with("firmware.bin", &[0u8; 256]);
        assert_eq!(call(&mut workspace, "firmware.find_load_address", json!({"width": 16})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "firmware.find_load_address", json!({"step": 1})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "firmware.find_load_address", json!({"min_string_len": 2})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "firmware.identify", json!({"start": 300})).unwrap_err().code, ErrorCode::OutOfRange);
    }
}
