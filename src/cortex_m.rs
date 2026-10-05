//! ARM Cortex-M vector table detection.
//!
//! A Cortex-M image starts its vector table with the initial main stack
//! pointer, followed by the addresses of the reset handler and the exception
//! handlers, then one entry per external interrupt (IRQ). Handlers run in
//! Thumb state, so every handler address has bit 0 set. The table must be
//! aligned to at least 128 bytes (VTOR), so it is looked for at offsets that
//! are multiples of 0x80.
//!
//! A table is accepted when:
//!
//! * the stack pointer is word aligned and inside a common SRAM region;
//! * the reset handler is a Thumb address;
//! * every named exception slot is either zero (unused) or a Thumb address
//!   near the reset handler, and enough of them are filled in.
//!
//! The table continues through IRQ entries until the first entry that is
//! neither zero nor a nearby Thumb address; trailing zeros are trimmed.

use crate::plugin::{Category, Detector, Field, Finding, ScanContext};

/// Bytes per vector table entry.
const ENTRY_BYTES: usize = 4;
/// Vector tables are aligned to at least this (the VTOR minimum).
pub const TABLE_ALIGNMENT: usize = 0x80;
/// Entries before the first external interrupt.
const SYSTEM_ENTRIES: usize = 16;
/// Largest table: 16 system entries and 240 interrupts.
const MAX_ENTRIES: usize = 256;
/// Fewest filled exception handlers (besides reset) for a convincing table.
const MIN_FILLED_EXCEPTIONS: usize = 3;
/// Handlers further than this from the reset handler are not trusted,
/// unless the document itself is larger.
const MIN_CODE_SPAN: u64 = 4 * 1024 * 1024;
/// Flash regions are assumed aligned to at least this when guessing a base.
const MIN_FLASH_REGION_ALIGNMENT: u64 = 1024 * 1024;
/// Most tables reported per scan.
const MAX_TABLES: usize = 64;
/// The Thumb state bit of a handler address.
const THUMB_BIT: u32 = 1;

/// Confidence of a table with only the minimum handlers filled in.
const BASE_CONFIDENCE: f32 = 0.6;
/// Confidence added per filled handler, up to [`MAX_CONFIDENCE`].
const CONFIDENCE_PER_HANDLER: f32 = 0.03;
const MAX_CONFIDENCE: f32 = 0.98;

/// SRAM regions where an initial stack pointer plausibly lies: the common
/// 0x2000_0000 SRAM (with Kinetis SRAM_L just below it) and the core-coupled
/// or LPC SRAM at 0x1000_0000. Ends are inclusive because the stack pointer
/// is the address just past the top of RAM.
const STACK_REGIONS: [(u32, u32); 2] = [(0x1FF0_0000, 0x2100_0000), (0x1000_0000, 0x1010_0000)];

/// Names of the system entries, by index.
const SYSTEM_NAMES: [&str; SYSTEM_ENTRIES] = [
    "Initial stack pointer",
    "Reset",
    "NMI",
    "HardFault",
    "MemManage",
    "BusFault",
    "UsageFault",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "SVCall",
    "DebugMonitor",
    "Reserved",
    "PendSV",
    "SysTick",
];
const STACK_POINTER_INDEX: usize = 0;
const RESET_INDEX: usize = 1;
/// Reserved system slots; some vendors store a checksum in them (NXP LPC uses
/// slot 7), so their values are not checked.
const RESERVED_INDICES: [usize; 5] = [7, 8, 9, 10, 13];

/// One entry of a vector table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorEntry {
    pub index: usize,
    /// "Reset", "HardFault", "IRQ 3" and so on.
    pub name: String,
    /// Document offset of the entry.
    pub offset: usize,
    pub value: u32,
}

impl VectorEntry {
    /// The handler's code address with the Thumb bit cleared, if it is a handler.
    pub fn handler_address(&self) -> Option<u32> {
        let is_handler = self.index != STACK_POINTER_INDEX && !RESERVED_INDICES.contains(&self.index) && self.value & THUMB_BIT != 0;
        is_handler.then_some(self.value & !THUMB_BIT)
    }
}

/// A detected Cortex-M vector table.
#[derive(Clone, Debug, PartialEq)]
pub struct VectorTable {
    /// Document offset of the table.
    pub offset: usize,
    pub initial_stack_pointer: u32,
    /// Reset handler as stored, with the Thumb bit.
    pub reset_handler: u32,
    /// Guessed address of document offset 0; see [`guess_flash_base`].
    pub inferred_flash_base: u64,
    /// Whether every handler falls inside the document under that guess.
    pub base_consistent: bool,
    /// Non-zero handler entries, including reset.
    pub valid_vectors: usize,
    /// Every entry up to the end of the table, stack pointer first.
    pub entries: Vec<VectorEntry>,
    pub confidence: f32,
}

impl VectorTable {
    pub fn len_bytes(&self) -> usize {
        self.entries.len() * ENTRY_BYTES
    }

    /// The entry with this name, such as "HardFault".
    pub fn entry(&self, name: &str) -> Option<&VectorEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// Document offset of a handler under the inferred base, if inside the document.
    pub fn handler_offset(&self, entry: &VectorEntry, document_len: usize) -> Option<usize> {
        let address = entry.handler_address()? as u64;
        let offset = address.checked_sub(self.inferred_flash_base)?;
        (offset < document_len as u64).then_some(offset as usize)
    }
}

/// Find vector tables in `bytes`, which sit at document offset `base_offset`
/// in a document of `document_len` bytes. Candidates are the offsets whose
/// document position is a multiple of [`TABLE_ALIGNMENT`].
pub fn find_vector_tables(bytes: &[u8], base_offset: usize, document_len: usize) -> Vec<VectorTable> {
    let first = (TABLE_ALIGNMENT - base_offset % TABLE_ALIGNMENT) % TABLE_ALIGNMENT;
    let document_len = document_len.max(base_offset + bytes.len());
    let mut tables = Vec::new();
    let mut at = first;
    while at + SYSTEM_ENTRIES * ENTRY_BYTES <= bytes.len() && tables.len() < MAX_TABLES {
        match parse_table(bytes, at, base_offset, document_len) {
            Some(table) => {
                at += table.len_bytes().div_ceil(TABLE_ALIGNMENT).max(1) * TABLE_ALIGNMENT;
                tables.push(table);
            }
            None => at += TABLE_ALIGNMENT,
        }
    }
    tables
}

fn read_word(bytes: &[u8], at: usize) -> Option<u32> {
    let chunk = bytes.get(at..at + ENTRY_BYTES)?;
    Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn is_plausible_stack_pointer(value: u32) -> bool {
    let word_aligned = value.is_multiple_of(ENTRY_BYTES as u32);
    word_aligned && STACK_REGIONS.iter().any(|&(low, high)| value >= low && value <= high)
}

/// Whether `value` is a Thumb handler within `span` bytes of the reset handler.
fn is_nearby_handler(value: u32, reset: u32, span: u64) -> bool {
    value & THUMB_BIT != 0 && (value as u64).abs_diff(reset as u64) <= span
}

fn entry_name(index: usize) -> String {
    match SYSTEM_NAMES.get(index) {
        Some(name) => (*name).to_string(),
        None => format!("IRQ {}", index - SYSTEM_ENTRIES),
    }
}

/// Parse a table at `bytes[at..]`, or `None` if it is not convincing.
fn parse_table(bytes: &[u8], at: usize, base_offset: usize, document_len: usize) -> Option<VectorTable> {
    let stack_pointer = read_word(bytes, at)?;
    if !is_plausible_stack_pointer(stack_pointer) {
        return None;
    }
    let reset = read_word(bytes, at + ENTRY_BYTES)?;
    if reset & THUMB_BIT == 0 || reset <= THUMB_BIT {
        return None;
    }
    let span = MIN_CODE_SPAN.max(document_len as u64);

    let mut values = vec![stack_pointer, reset];
    let mut filled_exceptions = 0;
    for index in RESET_INDEX + 1..SYSTEM_ENTRIES {
        let value = read_word(bytes, at + index * ENTRY_BYTES)?;
        if !RESERVED_INDICES.contains(&index) && value != 0 {
            if !is_nearby_handler(value, reset, span) {
                return None;
            }
            filled_exceptions += 1;
        }
        values.push(value);
    }
    if filled_exceptions < MIN_FILLED_EXCEPTIONS {
        return None;
    }
    while values.len() < MAX_ENTRIES {
        let Some(value) = read_word(bytes, at + values.len() * ENTRY_BYTES) else { break };
        if value != 0 && !is_nearby_handler(value, reset, span) {
            break;
        }
        values.push(value);
    }
    // Zero entries after the last interrupt are padding, not unused slots.
    while values.len() > SYSTEM_ENTRIES && values.last() == Some(&0) {
        values.pop();
    }

    let offset = base_offset + at;
    let entries: Vec<VectorEntry> = values
        .iter()
        .enumerate()
        .map(|(index, &value)| VectorEntry { index, name: entry_name(index), offset: offset + index * ENTRY_BYTES, value })
        .collect();
    let valid_vectors = entries.iter().filter(|entry| entry.handler_address().is_some()).count();
    let inferred_flash_base = guess_flash_base(reset, document_len);
    let base_consistent = entries
        .iter()
        .filter_map(VectorEntry::handler_address)
        .all(|address| (address as u64).checked_sub(inferred_flash_base).is_some_and(|offset| offset < document_len as u64));
    let confidence = (BASE_CONFIDENCE + CONFIDENCE_PER_HANDLER * valid_vectors as f32).min(MAX_CONFIDENCE);
    Some(VectorTable {
        offset,
        initial_stack_pointer: stack_pointer,
        reset_handler: reset,
        inferred_flash_base,
        base_consistent,
        valid_vectors,
        entries,
        confidence,
    })
}

/// Guess the address of document offset 0 from the reset handler.
///
/// Flash regions start on large power-of-two boundaries (0x0000_0000,
/// 0x0800_0000, 0x1000_0000 …), so the reset handler with its low bits
/// cleared is taken as the start of the region the document was dumped from.
/// The region alignment is the document size rounded up to a power of two,
/// and at least [`MIN_FLASH_REGION_ALIGNMENT`], so a reset handler late in a
/// large image still maps back to the region start. This assumes the file
/// starts at the start of flash; an application image linked above a
/// bootloader (say at 0x0800_8000) is reported at the region start instead,
/// which [`VectorTable::base_consistent`] does not catch.
pub fn guess_flash_base(reset_handler: u32, document_len: usize) -> u64 {
    let alignment = (document_len as u64).next_power_of_two().max(MIN_FLASH_REGION_ALIGNMENT);
    (reset_handler as u64) & !(alignment - 1)
}

/// The vector table detector, for the plugin registry.
pub struct CortexMVectorDetector;

impl CortexMVectorDetector {
    pub const ID: &'static str = "builtin.cortex_m_vectors";
}

impl Detector for CortexMVectorDetector {
    fn id(&self) -> &str {
        Self::ID
    }

    fn name(&self) -> &str {
        "ARM Cortex-M vector tables"
    }

    fn categories(&self) -> Vec<Category> {
        vec![Category::Executable]
    }

    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        find_vector_tables(window, context.base, context.document_len).iter().map(|table| table_finding(table, context.document_len)).collect()
    }
}

/// A finding with one field per vector.
pub fn table_finding(table: &VectorTable, document_len: usize) -> Finding {
    let fields: Vec<Field> = table
        .entries
        .iter()
        .map(|entry| Field::new(entry.name.clone(), entry.offset, ENTRY_BYTES, describe_entry(table, entry, document_len)))
        .collect();
    let base_note = if table.base_consistent { "" } else { " (handlers fall outside the file under this guess)" };
    let detail = format!(
        "stack pointer {:#010x}, reset handler {:#010x}, {} handlers, {} entries; flash base guess {:#x}{base_note}",
        table.initial_stack_pointer,
        table.reset_handler,
        table.valid_vectors,
        table.entries.len(),
        table.inferred_flash_base
    );
    Finding::new("executable:cortex-m-vectors", CortexMVectorDetector::ID, Category::Executable, table.offset, table.len_bytes())
        .title("ARM Cortex-M vector table")
        .detail(detail)
        .confidence(table.confidence)
        .sequence(ENTRY_BYTES, table.entries.len(), ENTRY_BYTES)
        .fields(fields)
}

fn describe_entry(table: &VectorTable, entry: &VectorEntry, document_len: usize) -> String {
    if entry.index == STACK_POINTER_INDEX {
        return format!("{:#010x}", entry.value);
    }
    if entry.value == 0 {
        return "0 (unused)".to_string();
    }
    match table.handler_offset(entry, document_len) {
        Some(offset) => format!("{:#010x} (Thumb, file offset {offset:#x})", entry.value),
        None if entry.handler_address().is_some() => format!("{:#010x} (Thumb)", entry.value),
        None => format!("{:#010x}", entry.value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STACK_TOP: u32 = 0x2000_5000;
    const RESET: u32 = 0x0800_01C1;
    const DEFAULT_HANDLER: u32 = 0x0800_0211;
    const IRQ_COUNT: usize = 20;

    /// A table as an STM32 linker script lays it out, followed by code.
    fn stm32_table() -> Vec<u32> {
        let mut words = vec![
            STACK_TOP,
            RESET,
            0x0800_0201, // NMI
            0x0800_0203, // HardFault
            0x0800_0205, // MemManage
            0x0800_0207, // BusFault
            0x0800_0209, // UsageFault
            0,
            0,
            0,
            0,
            0x0800_020B, // SVCall
            0x0800_020D, // DebugMonitor
            0,
            0x0800_020F, // PendSV
            0x0800_0213, // SysTick
        ];
        words.extend(std::iter::repeat_n(DEFAULT_HANDLER, IRQ_COUNT));
        words
    }

    fn image_with_table_at(table_offset: usize, words: &[u32], len: usize) -> Vec<u8> {
        let mut image = vec![0u8; len];
        for (index, word) in words.iter().enumerate() {
            let at = table_offset + index * ENTRY_BYTES;
            image[at..at + ENTRY_BYTES].copy_from_slice(&word.to_le_bytes());
        }
        // Thumb code straight after the table: "bx lr" pairs are even words,
        // so they end the interrupt list.
        let code_at = table_offset + words.len() * ENTRY_BYTES;
        for at in (code_at..(code_at + 64).min(len)).step_by(ENTRY_BYTES) {
            image[at..at + ENTRY_BYTES].copy_from_slice(&0x4770_4770u32.to_le_bytes());
        }
        image
    }

    #[test]
    fn detects_every_field_of_an_stm32_vector_table_at_offset_zero() {
        let words = stm32_table();
        let image = image_with_table_at(0, &words, 64 * 1024);
        let tables = find_vector_tables(&image, 0, image.len());
        assert_eq!(tables.len(), 1);
        let table = &tables[0];
        assert_eq!(table.offset, 0);
        assert_eq!(table.initial_stack_pointer, STACK_TOP);
        assert_eq!(table.reset_handler, RESET);
        assert_eq!(table.inferred_flash_base, 0x0800_0000);
        assert!(table.base_consistent);
        assert_eq!(table.entries.len(), SYSTEM_ENTRIES + IRQ_COUNT);
        // Reset, 9 named exceptions (DebugMonitor included) and the IRQs.
        assert_eq!(table.valid_vectors, 1 + 9 + IRQ_COUNT);
        let expected = [
            ("NMI", 0x0800_0201),
            ("HardFault", 0x0800_0203),
            ("MemManage", 0x0800_0205),
            ("BusFault", 0x0800_0207),
            ("UsageFault", 0x0800_0209),
            ("SVCall", 0x0800_020B),
            ("PendSV", 0x0800_020F),
            ("SysTick", 0x0800_0213),
        ];
        for (name, value) in expected {
            let entry = table.entry(name).unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(entry.value, value, "{name}");
            assert_eq!(entry.offset, entry.index * ENTRY_BYTES);
        }
        let irq = table.entry("IRQ 19").expect("last interrupt");
        assert_eq!((irq.value, irq.offset), (DEFAULT_HANDLER, (SYSTEM_ENTRIES + 19) * ENTRY_BYTES));
        let reset = table.entry("Reset").unwrap();
        assert_eq!(table.handler_offset(reset, image.len()), Some(0x1C0));
    }

    #[test]
    fn detector_reports_a_finding_with_a_field_per_vector() {
        let words = stm32_table();
        let image = image_with_table_at(0x200, &words, 16 * 1024);
        let context = ScanContext { base: 0x1000, document_len: 0x1000 + image.len(), strides: Vec::new() };
        let findings = CortexMVectorDetector.scan(&image, &context);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.category, Category::Executable);
        assert_eq!(finding.start, 0x1200);
        assert_eq!(finding.len, words.len() * ENTRY_BYTES);
        assert_eq!(finding.fields.len(), words.len());
        assert_eq!(finding.fields[0].name, "Initial stack pointer");
        assert_eq!(finding.fields[1].name, "Reset");
        assert_eq!(finding.fields[3].name, "HardFault");
        assert_eq!(finding.fields[3].offset, 0x1200 + 3 * ENTRY_BYTES);
        assert!(finding.detail.contains("0x20005000"), "{}", finding.detail);
        assert!(finding.confidence > 0.9);
    }

    #[test]
    fn tables_are_only_looked_for_on_128_byte_boundaries() {
        let words = stm32_table();
        let image = image_with_table_at(0x40, &words, 8 * 1024);
        assert!(find_vector_tables(&image, 0, image.len()).is_empty());
        // Alignment is judged in document offsets: the same bytes placed so the
        // table starts at document offset 0x80 are found.
        let tables = find_vector_tables(&image[0x40..], 0x80, image.len() + 0x40);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].offset, 0x80);
    }

    #[test]
    fn rejects_even_handlers_implausible_stacks_and_sparse_tables() {
        let mut even_reset = stm32_table();
        even_reset[RESET_INDEX] = 0x0800_01C0;
        let mut flash_stack = stm32_table();
        flash_stack[STACK_POINTER_INDEX] = 0x0800_4000;
        let mut far_handler = stm32_table();
        far_handler[3] = 0x6000_0001;
        let mut sparse = stm32_table();
        for slot in &mut sparse[2..SYSTEM_ENTRIES] {
            *slot = 0;
        }
        sparse[3] = 0x0800_0203;
        for (name, words) in [("even reset", even_reset), ("stack in flash", flash_stack), ("far handler", far_handler), ("sparse", sparse)] {
            let image = image_with_table_at(0, &words, 8 * 1024);
            assert!(find_vector_tables(&image, 0, image.len()).is_empty(), "{name}");
        }
    }

    #[test]
    fn reserved_slots_may_hold_a_vendor_checksum() {
        let mut words = stm32_table();
        words[7] = 0xEFFF_9D6C;
        let image = image_with_table_at(0, &words, 8 * 1024);
        assert_eq!(find_vector_tables(&image, 0, image.len()).len(), 1);
    }

    #[test]
    fn trailing_zero_padding_is_not_counted_as_interrupts() {
        let words = stm32_table();
        let mut image = vec![0u8; 8 * 1024];
        for (index, word) in words.iter().enumerate() {
            image[index * ENTRY_BYTES..(index + 1) * ENTRY_BYTES].copy_from_slice(&word.to_le_bytes());
        }
        let tables = find_vector_tables(&image, 0, image.len());
        assert_eq!(tables[0].entries.len(), words.len());
    }

    #[test]
    fn a_table_in_a_large_image_maps_back_to_the_start_of_flash() {
        // A 2 MiB image whose reset handler sits in its second MiB.
        assert_eq!(guess_flash_base(0x0810_0401, 2 * 1024 * 1024), 0x0800_0000);
        assert_eq!(guess_flash_base(0x0000_1235, 256 * 1024), 0);
        assert_eq!(guess_flash_base(0x1000_0235, 2 * 1024 * 1024), 0x1000_0000);
    }

    #[test]
    fn random_bytes_and_padding_give_no_tables_and_no_panics() {
        let mut state = 0x1234_5678u32;
        let noise: Vec<u8> = (0..256 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect();
        assert!(find_vector_tables(&noise, 0, noise.len()).is_empty());
        assert!(find_vector_tables(&[0u8; 4096], 0, 4096).is_empty());
        assert!(find_vector_tables(&[0xFFu8; 4096], 0, 4096).is_empty());
        let image = image_with_table_at(0, &stm32_table(), 4096);
        for len in 0..200 {
            let _ = find_vector_tables(&image[..len], 0, len);
        }
    }
}
