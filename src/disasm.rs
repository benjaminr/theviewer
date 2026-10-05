//! Disassembly through capstone, architecture detection from executable
//! headers and from raw code, and virtual-address to file-offset mapping.
//!
//! Decoding never stops early: a byte sequence capstone cannot decode becomes
//! a `.byte` pseudo-instruction and decoding resumes after it, so a listing of
//! mixed code and data always fills the view.


use capstone::arch::ArchOperand;
use capstone::arch::arm::ArmOperandType;
use capstone::arch::arm64::Arm64OperandType;
use capstone::arch::mips::MipsOperand;
use capstone::arch::ppc::PpcOperand;
use capstone::arch::riscv::RiscVOperand;
use capstone::arch::x86::X86OperandType;
use capstone::{Capstone, Endian, ExtraMode, Insn, InsnGroupId, Mode};

/// Instruction set architectures the viewer can disassemble.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    X86_64,
    X86_32,
    Arm64,
    Arm32,
    Thumb,
    RiscV64,
    RiscV32,
    Mips32,
    PowerPc32,
}

impl Arch {
    pub const ALL: [Arch; 9] = [
        Arch::X86_64,
        Arch::X86_32,
        Arch::Arm64,
        Arch::Arm32,
        Arch::Thumb,
        Arch::RiscV64,
        Arch::RiscV32,
        Arch::Mips32,
        Arch::PowerPc32,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86-64",
            Arch::X86_32 => "x86 (32-bit)",
            Arch::Arm64 => "ARM64",
            Arch::Arm32 => "ARM (32-bit)",
            Arch::Thumb => "ARM Thumb",
            Arch::RiscV64 => "RISC-V 64",
            Arch::RiscV32 => "RISC-V 32",
            Arch::Mips32 => "MIPS 32 (big endian)",
            Arch::PowerPc32 => "PowerPC 32 (big endian)",
        }
    }

    /// Smallest instruction length, used to step over undecodable bytes so
    /// decoding stays aligned on fixed-width architectures.
    pub fn min_instruction_len(self) -> usize {
        match self {
            Arch::X86_64 | Arch::X86_32 => 1,
            Arch::Thumb | Arch::RiscV64 | Arch::RiscV32 => 2,
            Arch::Arm64 | Arch::Arm32 | Arch::Mips32 | Arch::PowerPc32 => 4,
        }
    }

    /// Whether branch immediates are relative to the instruction's address
    /// rather than absolute targets (capstone reports RISC-V offsets raw).
    fn relative_branches(self) -> bool {
        matches!(self, Arch::RiscV64 | Arch::RiscV32)
    }
}

/// One decoded instruction, or a `.byte` placeholder for undecodable data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    /// Virtual address the instruction was decoded at.
    pub address: u64,
    /// Document offset of its first byte.
    pub offset: usize,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    /// Immediate jump or call target, as a virtual address.
    pub branch_target: Option<u64>,
    pub is_call: bool,
    pub is_return: bool,
}

impl Instruction {
    /// Whether this is a placeholder for bytes that did not decode.
    pub fn is_data(&self) -> bool {
        self.mnemonic == ".byte"
    }
}

// Capstone's architecture-independent instruction groups.
const GROUP_JUMP: u8 = 1;
const GROUP_CALL: u8 = 2;
const GROUP_RETURN: u8 = 3;
const GROUP_INTERRUPT_RETURN: u8 = 5;
const GROUP_RELATIVE_BRANCH: u8 = 7;

fn engine(arch: Arch) -> Result<Capstone, String> {
    use capstone::Arch as CsArch;
    let (cs_arch, mode, endian) = match arch {
        Arch::X86_64 => (CsArch::X86, Mode::Mode64, None),
        Arch::X86_32 => (CsArch::X86, Mode::Mode32, None),
        Arch::Arm64 => (CsArch::ARM64, Mode::Arm, None),
        Arch::Arm32 => (CsArch::ARM, Mode::Arm, None),
        Arch::Thumb => (CsArch::ARM, Mode::Thumb, None),
        Arch::RiscV64 => (CsArch::RISCV, Mode::RiscV64, None),
        Arch::RiscV32 => (CsArch::RISCV, Mode::RiscV32, None),
        Arch::Mips32 => (CsArch::MIPS, Mode::Mode32, Some(Endian::Big)),
        Arch::PowerPc32 => (CsArch::PPC, Mode::Mode32, Some(Endian::Big)),
    };
    // RISC-V binaries almost always use the compressed extension.
    let extra: Vec<ExtraMode> = if matches!(arch, Arch::RiscV64 | Arch::RiscV32) { vec![ExtraMode::RiscVC] } else { Vec::new() };
    let mut capstone = Capstone::new_raw(cs_arch, mode, extra.into_iter(), endian).map_err(|e| format!("capstone: {e}"))?;
    capstone.set_detail(true).map_err(|e| format!("capstone: {e}"))?;
    Ok(capstone)
}

/// Decode up to `max` instructions from `bytes`, which sit at document
/// offset `base_offset` and virtual address `address`.
pub fn disassemble(arch: Arch, bytes: &[u8], base_offset: usize, address: u64, max: usize) -> Result<Vec<Instruction>, String> {
    let capstone = engine(arch)?;
    let mut out = Vec::new();
    let mut position = 0usize;
    while position < bytes.len() && out.len() < max {
        let remaining = max - out.len();
        let decoded = capstone
            .disasm_count(&bytes[position..], address + position as u64, remaining)
            .map_err(|e| format!("capstone: {e}"))?;
        let mut consumed = 0usize;
        for insn in decoded.iter() {
            out.push(convert(&capstone, arch, insn, base_offset, address));
            consumed += insn.len();
        }
        position += consumed;
        if out.len() >= max || position >= bytes.len() {
            break;
        }
        // Capstone stops at the first byte it cannot decode: emit it as data.
        let step = arch.min_instruction_len().min(bytes.len() - position);
        out.push(data_placeholder(&bytes[position..position + step], base_offset + position, address + position as u64));
        position += step;
    }
    Ok(out)
}

fn data_placeholder(bytes: &[u8], offset: usize, address: u64) -> Instruction {
    let operands = bytes.iter().map(|b| format!("0x{b:02x}")).collect::<Vec<_>>().join(", ");
    Instruction {
        address,
        offset,
        len: bytes.len(),
        bytes: bytes.to_vec(),
        mnemonic: ".byte".to_string(),
        operands,
        branch_target: None,
        is_call: false,
        is_return: false,
    }
}

fn convert(capstone: &Capstone, arch: Arch, insn: &Insn, base_offset: usize, start_address: u64) -> Instruction {
    let address = insn.address();
    let mut instruction = Instruction {
        address,
        offset: base_offset + address.wrapping_sub(start_address) as usize,
        len: insn.len(),
        bytes: insn.bytes().to_vec(),
        mnemonic: insn.mnemonic().unwrap_or("?").to_string(),
        operands: insn.op_str().unwrap_or("").to_string(),
        branch_target: None,
        is_call: false,
        is_return: false,
    };
    if let Ok(detail) = capstone.insn_detail(insn) {
        let groups: Vec<u8> = detail.groups().iter().map(|InsnGroupId(id)| *id).collect();
        let branches = groups.iter().any(|g| matches!(*g, GROUP_JUMP | GROUP_CALL | GROUP_RELATIVE_BRANCH));
        instruction.is_call = groups.contains(&GROUP_CALL);
        instruction.is_return = groups.iter().any(|g| matches!(*g, GROUP_RETURN | GROUP_INTERRUPT_RETURN));
        if branches {
            let immediate = detail.arch_detail().operands().iter().rev().find_map(immediate_of);
            instruction.branch_target = immediate.map(|value| {
                if arch.relative_branches() { address.wrapping_add(value as u64) } else { value as u64 }
            });
        }
    }
    instruction
}

fn immediate_of(operand: &ArchOperand) -> Option<i64> {
    match operand {
        ArchOperand::X86Operand(op) => match op.op_type {
            X86OperandType::Imm(value) => Some(value),
            _ => None,
        },
        ArchOperand::Arm64Operand(op) => match op.op_type {
            Arm64OperandType::Imm(value) => Some(value),
            _ => None,
        },
        ArchOperand::ArmOperand(op) => match op.op_type {
            ArmOperandType::Imm(value) => Some(value as u32 as i64),
            _ => None,
        },
        ArchOperand::RiscVOperand(RiscVOperand::Imm(value)) => Some(*value),
        ArchOperand::MipsOperand(MipsOperand::Imm(value)) => Some(*value),
        ArchOperand::PpcOperand(PpcOperand::Imm(value)) => Some(*value),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Architecture from executable headers
// ---------------------------------------------------------------------------

/// Architecture and entry address from an ELF, PE or Mach-O header.
pub fn detect_arch(bytes: &[u8]) -> Option<(Arch, u64, String)> {
    crate::parsers::guarded(|| match goblin::Object::parse(bytes).ok()? {
        goblin::Object::Elf(elf) => {
            let arch = match (elf.header.e_machine, elf.is_64) {
                (62, _) => Arch::X86_64,
                (3, _) => Arch::X86_32,
                (183, _) => Arch::Arm64,
                (40, _) => Arch::Arm32,
                (243, true) => Arch::RiscV64,
                (243, false) => Arch::RiscV32,
                (8, _) => Arch::Mips32,
                (20, _) => Arch::PowerPc32,
                _ => return None,
            };
            Some((arch, elf.entry, format!("ELF header: machine {}, entry {:#x}", elf.header.e_machine, elf.entry)))
        }
        goblin::Object::PE(pe) => {
            let machine = pe.header.coff_header.machine;
            let arch = match machine {
                0x8664 => Arch::X86_64,
                0x014C => Arch::X86_32,
                0xAA64 => Arch::Arm64,
                0x01C4 => Arch::Thumb,
                0x01C0 => Arch::Arm32,
                0x5064 => Arch::RiscV64,
                0x5032 => Arch::RiscV32,
                _ => return None,
            };
            let entry = pe.image_base.wrapping_add(pe.entry as u64);
            Some((arch, entry, format!("PE header: machine {machine:#06x}, entry {entry:#x}")))
        }
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            let arch = macho_arch(macho.header.cputype)?;
            Some((arch, macho.entry, format!("Mach-O header: cputype {:#x}, entry {:#x}", macho.header.cputype, macho.entry)))
        }
        goblin::Object::Mach(goblin::mach::Mach::Fat(multi)) => {
            let first = multi.iter_arches().next()?.ok()?;
            let arch = macho_arch(first.cputype)?;
            Some((arch, 0, format!("universal binary, first slice cputype {:#x} at offset {:#x}", first.cputype, first.offset)))
        }
        _ => None,
    })
}

fn macho_arch(cputype: u32) -> Option<Arch> {
    const ABI64: u32 = 0x0100_0000;
    match cputype {
        t if t == 7 | ABI64 => Some(Arch::X86_64),
        7 => Some(Arch::X86_32),
        t if t == 12 | ABI64 => Some(Arch::Arm64),
        12 => Some(Arch::Arm32),
        18 => Some(Arch::PowerPc32),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Architecture from raw code
// ---------------------------------------------------------------------------

/// Most bytes examined when guessing.
const GUESS_WINDOW: usize = 4096;

/// Guess the architecture of headerless code by trying each one and scoring
/// how cleanly the bytes decode. Returns the winner only when it is clearly
/// ahead of the runner-up.
pub fn guess_arch(bytes: &[u8]) -> Option<(Arch, f32)> {
    let sample = &bytes[..bytes.len().min(GUESS_WINDOW)];
    if sample.len() < 8 {
        return None;
    }
    let mut scores: Vec<(Arch, f32)> = Arch::ALL.iter().map(|&arch| (arch, score_arch(arch, sample))).collect();
    scores.sort_by(|a, b| b.1.total_cmp(&a.1));
    let (best, best_score) = scores[0];
    let runner_up = scores.get(1).map(|s| s.1).unwrap_or(0.0);
    (best_score >= 0.5 && best_score - runner_up >= 0.05).then_some((best, best_score))
}

/// How much of the sample decodes as *typical* code for this architecture.
///
/// Dense encodings such as 32-bit ARM and Thumb decode almost any bytes, so
/// validity alone cannot tell architectures apart. Each instruction instead
/// counts fully when it is one of the architecture's everyday instructions,
/// a quarter when it is valid but unusual, and not at all when it is data.
/// A bonus is added for typical prologues and epilogues.
fn score_arch(arch: Arch, sample: &[u8]) -> f32 {
    let Ok(instructions) = disassemble(arch, sample, 0, 0, sample.len()) else { return 0.0 };
    let mut weighted = 0.0f32;
    for instruction in &instructions {
        if instruction.is_data() || is_implausible(&instruction.mnemonic) {
            continue;
        }
        let weight = if is_typical(arch, instruction) { 1.0 } else { 0.25 };
        weighted += instruction.len as f32 * weight;
    }
    let base = weighted / sample.len() as f32;
    (base + prologue_bonus(arch, sample)).min(1.0)
}

/// Whether an instruction is one compilers emit constantly on `arch`.
fn is_typical(arch: Arch, instruction: &Instruction) -> bool {
    let mnemonic = instruction.mnemonic.as_str();
    let one_of = |list: &[&str]| list.contains(&mnemonic);
    // In 32-bit mode, the REX prefixes of 64-bit code (0x40 to 0x4F) decode
    // as one-byte inc/dec; seeing many of them is evidence for x86-64.
    if arch == Arch::X86_32 && instruction.len == 1 && (0x40..=0x4F).contains(&instruction.bytes[0]) {
        return false;
    }
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            one_of(&[
                "mov", "push", "pop", "call", "ret", "jmp", "lea", "add", "sub", "cmp", "test", "xor", "and", "or", "nop", "movzx",
                "movsx", "movsxd", "imul", "shl", "shr", "sar", "leave", "endbr64", "inc", "dec", "neg", "not", "movq", "movd", "movss",
                "movsd", "movaps", "movups", "cdqe", "cqo",
            ]) || mnemonic.starts_with('j')
                || mnemonic.starts_with("cmov")
                || mnemonic.starts_with("set")
        }
        Arch::Arm64 => {
            one_of(&[
                "stp", "ldp", "mov", "ldr", "str", "ldrb", "strb", "ldrh", "strh", "ldur", "stur", "add", "sub", "adds", "subs", "bl", "b",
                "br", "blr", "cbz", "cbnz", "tbz", "tbnz", "ret", "adrp", "adr", "cmp", "cmn", "orr", "and", "eor", "lsl", "lsr", "asr",
                "movz", "movk", "movn", "csel", "cset", "csinc", "nop", "madd", "mul", "udiv", "sdiv", "sxtw", "uxtb", "tst", "ubfx", "sbfx",
            ]) || mnemonic.starts_with("b.")
        }
        Arch::Arm32 => {
            // Real ARM code is overwhelmingly unconditional: condition 0xE.
            let condition = instruction.bytes.get(3).map(|b| b >> 4);
            condition == Some(0xE)
                && one_of(&["push", "pop", "mov", "ldr", "str", "ldrb", "strb", "add", "sub", "bl", "b", "bx", "cmp", "orr", "and", "lsl", "lsr", "mvn", "ldm", "stm", "blx"])
        }
        Arch::Thumb => one_of(&[
            "push", "pop", "mov", "movs", "ldr", "str", "ldrb", "strb", "add", "adds", "sub", "subs", "bl", "b", "bx", "blx", "cmp", "beq",
            "bne", "cbz", "cbnz", "lsls", "lsrs", "ands", "orrs", "it", "ldr.w", "str.w",
        ]),
        Arch::RiscV64 | Arch::RiscV32 => {
            let base = mnemonic.trim_start_matches("c.");
            ["addi", "addiw", "sd", "ld", "sw", "lw", "jal", "jalr", "beq", "bne", "blt", "bge", "bltu", "bgeu", "auipc", "lui", "add", "sub", "li", "mv", "ret", "j", "nop", "slli", "srli", "andi", "beqz", "bnez", "sdsp", "ldsp", "addi16sp", "addi4spn"]
                .contains(&base)
        }
        Arch::Mips32 => one_of(&["addiu", "lw", "sw", "jal", "jr", "nop", "lui", "ori", "beq", "bne", "move", "addu", "subu", "sll", "srl", "lb", "sb", "slt", "sltu", "b", "beqz", "bnez", "li", "jalr"]),
        Arch::PowerPc32 => one_of(&["stwu", "mflr", "mtlr", "stw", "lwz", "addi", "li", "lis", "bl", "blr", "mr", "cmpwi", "cmplwi", "beq", "bne", "b", "ori", "stmw", "lmw", "add", "subf", "rlwinm", "nop"]),
    }
}

/// Instructions that are valid but almost never appear in ordinary code, so
/// decoding random data as them is evidence against an architecture.
fn is_implausible(mnemonic: &str) -> bool {
    const RARE: [&str; 22] = [
        "in", "out", "insb", "insd", "outsb", "outsd", "hlt", "cli", "sti", "lock", "bound", "into", "aaa", "aas", "daa", "das", "arpl",
        "les", "lds", "salc", "fwait", "udf",
    ];
    RARE.contains(&mnemonic) || mnemonic.starts_with("ud") || mnemonic.starts_with("invalid")
}

fn prologue_bonus(arch: Arch, sample: &[u8]) -> f32 {
    let contains = |needle: &[u8]| sample.windows(needle.len()).filter(|w| *w == needle).count();
    let hits = match arch {
        Arch::X86_64 => contains(&[0x55, 0x48, 0x89, 0xE5]) + contains(&[0x48, 0x83, 0xEC]) + contains(&[0x48, 0x89, 0x5C, 0x24]),
        Arch::X86_32 => contains(&[0x55, 0x89, 0xE5]),
        // stp x29, x30, [sp, #-N]! and ret
        Arch::Arm64 => contains(&[0xFD, 0x7B]) + contains(&[0xC0, 0x03, 0x5F, 0xD6]),
        // push {.., lr} and bx lr
        Arch::Arm32 => contains(&[0x2D, 0xE9]) + contains(&[0x1E, 0xFF, 0x2F, 0xE1]),
        Arch::Thumb => contains(&[0x70, 0x47]),
        // addi sp, sp, -N and ret
        Arch::RiscV64 | Arch::RiscV32 => contains(&[0x13, 0x01, 0x01]) + contains(&[0x67, 0x80, 0x00, 0x00]),
        Arch::Mips32 => contains(&[0x27, 0xBD, 0xFF]) + contains(&[0x03, 0xE0, 0x00, 0x08]),
        Arch::PowerPc32 => contains(&[0x94, 0x21, 0xFF]) + contains(&[0x4E, 0x80, 0x00, 0x20]),
    };
    (hits as f32 * 0.05).min(0.2)
}

// ---------------------------------------------------------------------------
// Virtual addresses and file offsets
// ---------------------------------------------------------------------------

/// Mapping between virtual addresses and file offsets from an executable's
/// segments or sections.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressMap {
    /// (virtual address, size in the file, file offset), sorted by address.
    ranges: Vec<(u64, u64, usize)>,
}

impl AddressMap {
    pub fn from_executable(bytes: &[u8]) -> Option<AddressMap> {
        let mut ranges = crate::parsers::guarded(|| executable_ranges(bytes))?;
        ranges.retain(|&(_, size, offset)| size > 0 && offset < bytes.len());
        ranges.sort_by_key(|&(address, _, _)| address);
        (!ranges.is_empty()).then_some(AddressMap { ranges })
    }

    /// File offset holding the byte at `address`.
    pub fn offset_of(&self, address: u64) -> Option<usize> {
        self.ranges
            .iter()
            .find(|&&(start, size, _)| address >= start && address - start < size)
            .map(|&(start, _, offset)| offset + (address - start) as usize)
    }

    /// Virtual address of the byte at file `offset`.
    pub fn address_of(&self, offset: usize) -> Option<u64> {
        self.ranges
            .iter()
            .find(|&&(_, size, file)| offset >= file && ((offset - file) as u64) < size)
            .map(|&(start, _, file)| start + (offset - file) as u64)
    }

    pub fn ranges(&self) -> &[(u64, u64, usize)] {
        &self.ranges
    }
}

fn executable_ranges(bytes: &[u8]) -> Option<Vec<(u64, u64, usize)>> {
    match goblin::Object::parse(bytes).ok()? {
        goblin::Object::Elf(elf) => {
            const PT_LOAD: u32 = 1;
            let mut ranges: Vec<(u64, u64, usize)> = elf
                .program_headers
                .iter()
                .filter(|header| header.p_type == PT_LOAD)
                .map(|header| (header.p_vaddr, header.p_filesz, header.p_offset as usize))
                .collect();
            if ranges.is_empty() {
                // Relocatable objects have sections but no segments.
                ranges = elf
                    .section_headers
                    .iter()
                    .filter(|section| section.sh_addr != 0 && section.sh_type != 8)
                    .map(|section| (section.sh_addr, section.sh_size, section.sh_offset as usize))
                    .collect();
            }
            Some(ranges)
        }
        goblin::Object::PE(pe) => {
            let mut ranges: Vec<(u64, u64, usize)> = pe
                .sections
                .iter()
                .map(|section| {
                    let size = section.size_of_raw_data.min(section.virtual_size.max(section.size_of_raw_data));
                    (pe.image_base + section.virtual_address as u64, size as u64, section.pointer_to_raw_data as usize)
                })
                .collect();
            // Headers map to the image base too.
            ranges.push((pe.image_base, 0x400, 0));
            Some(ranges)
        }
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => Some(
            macho
                .segments
                .iter()
                .filter(|segment| segment.filesize > 0)
                .map(|segment| (segment.vmaddr, segment.filesize, segment.fileoff as usize))
                .collect(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_function_decodes_with_call_target_and_return() {
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let listing = disassemble(Arch::X86_64, &bytes, 100, 0x1000, 50).unwrap();
        let mnemonics: Vec<&str> = listing.iter().map(|i| i.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["push", "mov", "call", "ret"]);
        assert_eq!(listing[0].offset, 100);
        assert_eq!(listing[2].offset, 104);
        assert!(listing[2].is_call);
        assert_eq!(listing[2].branch_target, Some(0x1009));
        assert!(listing[3].is_return);
    }

    #[test]
    fn arm64_and_riscv_decode() {
        let arm = [0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91, 0xC0, 0x03, 0x5F, 0xD6];
        let listing = disassemble(Arch::Arm64, &arm, 0, 0, 10).unwrap();
        let mnemonics: Vec<&str> = listing.iter().map(|i| i.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["stp", "mov", "ret"]);
        assert!(listing[2].is_return);

        let riscv = [0x13, 0x01, 0x01, 0xFF, 0x67, 0x80, 0x00, 0x00];
        let listing = disassemble(Arch::RiscV64, &riscv, 0, 0, 10).unwrap();
        assert_eq!(listing.len(), 2);
        assert_eq!(listing[0].mnemonic, "addi");
        assert!(listing.iter().all(|i| !i.is_data()));
    }

    #[test]
    fn undecodable_bytes_become_data_and_decoding_continues() {
        // 0x06 (push es) is invalid in 64-bit mode; the ret after it must still decode.
        let bytes = [0x90, 0x06, 0x90, 0xC3];
        let listing = disassemble(Arch::X86_64, &bytes, 0, 0, 10).unwrap();
        let mnemonics: Vec<&str> = listing.iter().map(|i| i.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["nop", ".byte", "nop", "ret"]);
        assert_eq!(listing[1].operands, "0x06");
        // Fixed-width architectures step a whole word.
        let listing = disassemble(Arch::Arm64, &[0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x03, 0x5F, 0xD6], 0, 0, 10).unwrap();
        assert_eq!(listing[0].len, 4);
        assert_eq!(listing.last().unwrap().mnemonic, "ret");
    }

    #[test]
    fn max_limits_the_listing() {
        let bytes = [0x90u8; 64];
        assert_eq!(disassemble(Arch::X86_64, &bytes, 0, 0, 5).unwrap().len(), 5);
    }

    #[test]
    fn detects_the_architecture_of_the_running_binary_and_a_minimal_elf() {
        let own = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let (arch, _entry, why) = detect_arch(&own).expect("own binary");
        assert!(matches!(arch, Arch::Arm64 | Arch::X86_64), "{arch:?} {why}");

        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7FELF");
        elf[4] = 2; // 64-bit
        elf[5] = 1; // little endian
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // executable
        elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        let (arch, entry, _) = detect_arch(&elf).expect("minimal ELF");
        assert_eq!((arch, entry), (Arch::X86_64, 0x401000));
        assert!(detect_arch(b"not an executable at all").is_none());
    }

    #[test]
    fn guesses_architecture_of_headerless_code() {
        // A few typical x86-64 functions.
        let x86: Vec<u8> = [
            &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x89, 0x7D, 0xFC, 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x01, 0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3][..],
            &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xF8, 0x48, 0x8B, 0x45, 0xF8, 0x48, 0x8B, 0x00, 0x5D, 0xC3][..],
            &[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3][..],
        ]
        .iter()
        .flat_map(|f| f.iter().copied())
        .cycle()
        .take(256)
        .collect();
        let scores: Vec<(Arch, f32)> = Arch::ALL.iter().map(|&a| (a, score_arch(a, &x86))).collect();
        assert_eq!(guess_arch(&x86).map(|(arch, _)| arch), Some(Arch::X86_64), "{scores:?}");

        // ARM64 functions: stp/mov/add/ldp/ret.
        let words: [u32; 8] = [0xA9BF7BFD, 0x910003FD, 0x11000400, 0x8B010000, 0xF9400000, 0xA8C17BFD, 0xD65F03C0, 0xD503201F];
        let arm: Vec<u8> = words.iter().cycle().take(64).flat_map(|w| w.to_le_bytes()).collect();
        let scores: Vec<(Arch, f32)> = Arch::ALL.iter().map(|&a| (a, score_arch(a, &arm))).collect();
        assert_eq!(guess_arch(&arm).map(|(arch, _)| arch), Some(Arch::Arm64), "{scores:?}");

        // Random bytes are not confidently any architecture.
        let mut state = 0x5EEDu32;
        let noise: Vec<u8> = (0..2048)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect();
        let scores: Vec<(Arch, f32)> = Arch::ALL.iter().map(|&a| (a, score_arch(a, &noise))).collect();
        assert_eq!(guess_arch(&noise), None, "{scores:?}");
    }

    #[test]
    fn address_map_places_the_entry_point_inside_the_file() {
        let own = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let (_, entry, _) = detect_arch(&own).unwrap();
        let map = AddressMap::from_executable(&own).expect("address map");
        let offset = map.offset_of(entry).expect("entry maps to a file offset");
        assert!(offset > 0 && offset < own.len());
        assert_eq!(map.address_of(offset), Some(entry));
    }
}
