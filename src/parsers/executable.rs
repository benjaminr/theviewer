//! Executable formats via goblin: ELF, PE and Mach-O (including fat binaries).

use goblin::elf::Elf;
use goblin::mach::{Mach, MachO};
use goblin::pe::PE;

use super::{MAX_CHILDREN, MAX_EXTENT, guarded, u32le};
use crate::plugin::{Category, Field, Finding, Parser};

const SOURCE: &str = "parsers.executable";

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

pub struct ElfParser;

impl Parser for ElfParser {
    fn id(&self) -> &str {
        "elf"
    }

    fn name(&self) -> &str {
        "ELF executable"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"\x7FELF")
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        let elf = guarded(|| Elf::parse(bytes).ok())?;
        let header_len = if elf.is_64 { 64 } else { 52 };
        let class = if elf.is_64 { "64-bit" } else { "32-bit" };
        let endian = if elf.little_endian { "LSB" } else { "MSB" };
        let kind = goblin::elf::header::et_to_str(elf.header.e_type);
        let machine = goblin::elf::header::machine_to_str(elf.header.e_machine);

        let mut header = Field::new("ELF header", base, header_len, format!("{class} {endian}")).with_children(vec![
            Field::new("e_ident", base, 16, format!("class {class}, data {endian}, version {}", bytes.get(6).copied().unwrap_or(0))),
            Field::new("e_type", base + 16, 2, kind.to_string()),
            Field::new("e_machine", base + 18, 2, machine.to_string()),
            Field::new("e_entry", base + 24, if elf.is_64 { 8 } else { 4 }, format!("{:#x}", elf.header.e_entry)),
            Field::new("e_phoff", base + if elf.is_64 { 32 } else { 28 }, if elf.is_64 { 8 } else { 4 }, format!("{:#x}", elf.header.e_phoff)),
            Field::new("e_shoff", base + if elf.is_64 { 40 } else { 32 }, if elf.is_64 { 8 } else { 4 }, format!("{:#x}", elf.header.e_shoff)),
        ]);
        header.children.push(Field::new("e_phnum", base + if elf.is_64 { 56 } else { 44 }, 2, elf.header.e_phnum.to_string()));
        header.children.push(Field::new("e_shnum", base + if elf.is_64 { 60 } else { 48 }, 2, elf.header.e_shnum.to_string()));

        let mut extent = header_len;
        let phentsize = elf.header.e_phentsize as usize;
        let mut program_headers = Vec::new();
        for (index, ph) in elf.program_headers.iter().take(MAX_CHILDREN).enumerate() {
            let at = elf.header.e_phoff as usize + index * phentsize;
            let kind = goblin::elf::program_header::pt_to_str(ph.p_type);
            program_headers.push(Field::new(
                kind.to_string(),
                base + at,
                phentsize,
                format!("offset {:#x}, filesz {:#x}, vaddr {:#x}", ph.p_offset, ph.p_filesz, ph.p_vaddr),
            ));
            extent = extent.max((ph.p_offset + ph.p_filesz) as usize);
        }
        let shentsize = elf.header.e_shentsize as usize;
        let mut section_headers = Vec::new();
        for (index, sh) in elf.section_headers.iter().take(MAX_CHILDREN).enumerate() {
            let at = elf.header.e_shoff as usize + index * shentsize;
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            section_headers.push(Field::new(
                if name.is_empty() { format!("section {index}") } else { name.to_string() },
                base + at,
                shentsize,
                format!("offset {:#x}, size {:#x}, addr {:#x}", sh.sh_offset, sh.sh_size, sh.sh_addr),
            ));
            // SHT_NOBITS sections occupy no file space.
            if sh.sh_type != goblin::elf::section_header::SHT_NOBITS {
                extent = extent.max((sh.sh_offset + sh.sh_size) as usize);
            }
            extent = extent.max(at + shentsize);
        }
        extent = extent.min(bytes.len()).min(MAX_EXTENT);

        let mut fields = vec![header];
        if !program_headers.is_empty() {
            let span = elf.program_headers.len() * phentsize;
            fields.push(Field::new("Program headers", base + elf.header.e_phoff as usize, span, format!("{} entries", elf.program_headers.len())).with_children(program_headers));
        }
        if !section_headers.is_empty() {
            let span = elf.section_headers.len() * shentsize;
            fields.push(Field::new("Section headers", base + elf.header.e_shoff as usize, span, format!("{} entries", elf.section_headers.len())).with_children(section_headers));
        }

        Some(
            Finding::new("elf", SOURCE, Category::Executable, base, extent.max(header_len))
                .title("ELF executable")
                .detail(format!(
                    "ELF {class} {endian} {kind}, {machine}, {} sections, {} segments, entry {:#x}",
                    elf.section_headers.len(),
                    elf.program_headers.len(),
                    elf.entry
                ))
                .fields(fields),
        )
    }
}

// ---------------------------------------------------------------------------
// PE
// ---------------------------------------------------------------------------

pub struct PeParser;

/// Offset of the PE signature, if the MZ header points at one within `bytes`.
fn pe_signature_offset(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    let pointer = u32le(bytes, 0x3C)? as usize;
    (bytes.get(pointer..pointer + 4)? == b"PE\0\0").then_some(pointer)
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014C => "x86",
        0x8664 => "x86-64",
        0x01C0 => "ARM",
        0xAA64 => "ARM64",
        0x01C4 => "ARM Thumb-2",
        0x0200 => "Itanium",
        0x5032 => "RISC-V 32",
        0x5064 => "RISC-V 64",
        0 => "unknown",
        _ => "other",
    }
}

impl Parser for PeParser {
    fn id(&self) -> &str {
        "pe"
    }

    fn name(&self) -> &str {
        "Windows PE executable"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        pe_signature_offset(bytes).is_some()
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        let signature_at = pe_signature_offset(bytes)?;
        let pe = guarded(|| PE::parse(bytes).ok())?;
        let coff = &pe.header.coff_header;
        let optional_size = coff.size_of_optional_header as usize;
        let coff_at = signature_at + 4;
        let optional_at = coff_at + 20;
        let sections_at = optional_at + optional_size;

        let mut fields = vec![
            Field::new("DOS header", base, 64, "MZ").with_children(vec![Field::new("e_lfanew", base + 0x3C, 4, format!("{signature_at:#x}"))]),
            Field::new("PE signature", base + signature_at, 4, "PE\\0\\0"),
            Field::new("COFF header", base + coff_at, 20, machine_name(coff.machine)).with_children(vec![
                Field::new("Machine", base + coff_at, 2, format!("{} ({:#x})", machine_name(coff.machine), coff.machine)),
                Field::new("NumberOfSections", base + coff_at + 2, 2, coff.number_of_sections.to_string()),
                Field::new("TimeDateStamp", base + coff_at + 4, 4, coff.time_date_stamp.to_string()),
                Field::new("SizeOfOptionalHeader", base + coff_at + 16, 2, optional_size.to_string()),
                Field::new("Characteristics", base + coff_at + 18, 2, format!("{:#06x}", coff.characteristics)),
            ]),
        ];

        let mut is_dotnet = false;
        if let Some(optional) = &pe.header.optional_header {
            let magic = optional.standard_fields.magic;
            let magic_name = match magic {
                0x10B => "PE32",
                0x20B => "PE32+",
                _ => "unknown",
            };
            is_dotnet = optional.data_directories.get_clr_runtime_header().is_some();
            fields.push(
                Field::new("Optional header", base + optional_at, optional_size, magic_name).with_children(vec![
                    Field::new("Magic", base + optional_at, 2, format!("{magic_name} ({magic:#x})")),
                    Field::new("AddressOfEntryPoint", base + optional_at + 16, 4, format!("{:#x}", optional.standard_fields.address_of_entry_point)),
                    Field::new("ImageBase", base + optional_at + if pe.is_64 { 24 } else { 28 }, if pe.is_64 { 8 } else { 4 }, format!("{:#x}", pe.image_base)),
                    Field::new("Subsystem", base + optional_at + 68, 2, optional.windows_fields.subsystem.to_string()),
                ]),
            );
        }

        let mut extent = sections_at;
        let mut sections = Vec::new();
        for (index, section) in pe.sections.iter().take(MAX_CHILDREN).enumerate() {
            let at = sections_at + index * 40;
            let name = section.real_name.clone().unwrap_or_else(|| super::fixed_string(&section.name));
            sections.push(Field::new(
                name,
                base + at,
                40,
                format!(
                    "vaddr {:#x}, vsize {:#x}, raw {:#x}+{:#x}",
                    section.virtual_address, section.virtual_size, section.pointer_to_raw_data, section.size_of_raw_data
                ),
            ));
            extent = extent.max(section.pointer_to_raw_data as usize + section.size_of_raw_data as usize);
            extent = extent.max(at + 40);
        }
        if !sections.is_empty() {
            fields.push(Field::new("Sections", base + sections_at, pe.sections.len() * 40, format!("{} sections", pe.sections.len())).with_children(sections));
        }
        extent = extent.min(bytes.len()).min(MAX_EXTENT);

        let kind = if pe.is_lib { "DLL" } else { "executable" };
        let bits = if pe.is_64 { "64-bit" } else { "32-bit" };
        let dotnet = if is_dotnet { ", .NET assembly" } else { "" };
        Some(
            Finding::new("pe", SOURCE, Category::Executable, base, extent)
                .title("Windows PE executable")
                .detail(format!(
                    "PE {bits} {kind}, {}, {} sections, entry {:#x}{dotnet}",
                    machine_name(coff.machine),
                    pe.sections.len(),
                    pe.entry
                ))
                .fields(fields),
        )
    }
}

// ---------------------------------------------------------------------------
// Mach-O
// ---------------------------------------------------------------------------

pub struct MachOParser;

const MACHO_MAGICS: [[u8; 4]; 4] = [[0xFE, 0xED, 0xFA, 0xCE], [0xFE, 0xED, 0xFA, 0xCF], [0xCE, 0xFA, 0xED, 0xFE], [0xCF, 0xFA, 0xED, 0xFE]];
const FAT_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

/// A fat header is distinguished from a Java class file by a small
/// architecture count where Java keeps its minor version.
fn looks_like_fat(bytes: &[u8]) -> bool {
    bytes.starts_with(&FAT_MAGIC) && super::u32be(bytes, 4).is_some_and(|count| (1..=20).contains(&count))
}

fn arch_name(cputype: u32, cpusubtype: u32) -> String {
    goblin::mach::cputype::get_arch_name_from_types(cputype, cpusubtype)
        .map(str::to_string)
        .unwrap_or_else(|| format!("cputype {cputype:#x}"))
}

fn command_name(command: &goblin::mach::load_command::CommandVariant) -> String {
    let debug = format!("{command:?}");
    debug.split('(').next().unwrap_or("LC_?").to_string()
}

impl Parser for MachOParser {
    fn id(&self) -> &str {
        "macho"
    }

    fn name(&self) -> &str {
        "Mach-O executable"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        MACHO_MAGICS.iter().any(|magic| bytes.starts_with(magic)) || looks_like_fat(bytes)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        let mach = guarded(|| Mach::parse(bytes).ok())?;
        match mach {
            Mach::Fat(fat) => {
                let mut arches = Vec::new();
                let mut extent = 8;
                let mut names = Vec::new();
                for (index, arch) in fat.iter_arches().take(MAX_CHILDREN).enumerate() {
                    let arch = arch.ok()?;
                    let name = arch_name(arch.cputype, arch.cpusubtype);
                    arches.push(Field::new(
                        name.clone(),
                        base + 8 + index * 20,
                        20,
                        format!("offset {:#x}, size {:#x}", arch.offset, arch.size),
                    ));
                    let slice_end = arch.offset as usize + arch.size as usize;
                    extent = extent.max(slice_end);
                    names.push(name);
                }
                let extent = extent.min(bytes.len()).min(MAX_EXTENT);
                let header = Field::new("Fat header", base, 8, format!("{} architectures", fat.narches)).with_children(arches);
                Some(
                    Finding::new("macho-fat", SOURCE, Category::Executable, base, extent)
                        .title("Mach-O universal binary")
                        .detail(format!("Universal binary: {}", names.join(", ")))
                        .fields(vec![header]),
                )
            }
            Mach::Binary(macho) => Some(describe_macho(&macho, bytes, base)),
        }
    }
}

fn describe_macho(macho: &MachO<'_>, bytes: &[u8], base: usize) -> Finding {
    let header = &macho.header;
    let is_64 = macho.is_64;
    let header_len = if is_64 { 32 } else { 28 };
    let arch = arch_name(header.cputype, header.cpusubtype);
    let filetype = goblin::mach::header::filetype_to_str(header.filetype);

    let header_field = Field::new("Mach header", base, header_len, arch.clone()).with_children(vec![
        Field::new("magic", base, 4, format!("{:#x}", header.magic)),
        Field::new("cputype", base + 4, 4, arch.clone()),
        Field::new("filetype", base + 12, 4, filetype.to_string()),
        Field::new("ncmds", base + 16, 4, header.ncmds.to_string()),
        Field::new("sizeofcmds", base + 20, 4, header.sizeofcmds.to_string()),
        Field::new("flags", base + 24, 4, format!("{:#x}", header.flags)),
    ]);

    let mut extent = header_len + header.sizeofcmds as usize;
    let mut commands = Vec::new();
    let offsets: Vec<usize> = macho.load_commands.iter().map(|lc| lc.offset).collect();
    for (index, command) in macho.load_commands.iter().take(MAX_CHILDREN).enumerate() {
        let next = offsets.get(index + 1).copied().unwrap_or(header_len + header.sizeofcmds as usize);
        let len = next.saturating_sub(command.offset).max(8);
        let value = match &command.command {
            goblin::mach::load_command::CommandVariant::LoadDylib(dylib)
            | goblin::mach::load_command::CommandVariant::LoadWeakDylib(dylib)
            | goblin::mach::load_command::CommandVariant::ReexportDylib(dylib) => {
                let name_offset = dylib.dylib.name as usize;
                super::fixed_string(bytes.get(command.offset + name_offset..next).unwrap_or(&[]))
            }
            goblin::mach::load_command::CommandVariant::Main(main) => format!("entry offset {:#x}", main.entryoff),
            goblin::mach::load_command::CommandVariant::Uuid(uuid) => super::hex_preview(&uuid.uuid, 16),
            _ => String::new(),
        };
        commands.push(Field::new(command_name(&command.command), base + command.offset, len, value));
    }

    let mut segments = Vec::new();
    for segment in macho.segments.iter().take(MAX_CHILDREN) {
        let name = segment.name().unwrap_or("?").to_string();
        let mut sections = Vec::new();
        if let Ok(list) = segment.sections() {
            for (section, _) in list.iter().take(MAX_CHILDREN) {
                let section_name = section.name().unwrap_or("?").to_string();
                sections.push(Field::new(
                    section_name,
                    base + section.offset as usize,
                    section.size as usize,
                    format!("addr {:#x}, size {:#x}", section.addr, section.size),
                ));
                extent = extent.max(section.offset as usize + section.size as usize);
            }
        }
        extent = extent.max(segment.fileoff as usize + segment.filesize as usize);
        segments.push(
            Field::new(
                name,
                base + segment.fileoff as usize,
                segment.filesize as usize,
                format!("vmaddr {:#x}, fileoff {:#x}, filesize {:#x}, {} sections", segment.vmaddr, segment.fileoff, segment.filesize, segment.nsects),
            )
            .with_children(sections),
        );
    }
    let extent = extent.min(bytes.len()).min(MAX_EXTENT);

    let mut fields = vec![header_field];
    if !commands.is_empty() {
        fields.push(Field::new("Load commands", base + header_len, header.sizeofcmds as usize, format!("{} commands", macho.load_commands.len())).with_children(commands));
    }
    if !segments.is_empty() {
        fields.push(Field::new("Segments", base, extent, format!("{} segments", macho.segments.len())).with_children(segments));
    }

    Finding::new("macho", SOURCE, Category::Executable, base, extent)
        .title("Mach-O executable")
        .detail(format!(
            "Mach-O {} {filetype}, {arch}, {} load commands, {} segments, entry {:#x}",
            if is_64 { "64-bit" } else { "32-bit" },
            macho.load_commands.len(),
            macho.segments.len(),
            macho.entry
        ))
        .fields(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal 64-bit little-endian ELF: header plus one section header.
    fn minimal_elf() -> Vec<u8> {
        let mut bytes = vec![0u8; 64 + 64];
        bytes[..4].copy_from_slice(b"\x7FELF");
        bytes[4] = 2; // 64-bit
        bytes[5] = 1; // little endian
        bytes[6] = 1; // version
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        bytes[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // x86-64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // entry
        bytes[40..48].copy_from_slice(&64u64.to_le_bytes()); // shoff
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
        bytes[60..62].copy_from_slice(&1u16.to_le_bytes()); // shnum
        bytes[62..64].copy_from_slice(&0u16.to_le_bytes()); // shstrndx
        // One null section header (all zero) is valid.
        bytes
    }

    /// A minimal PE32 image: DOS stub, PE signature, COFF header, optional header, one section.
    fn minimal_pe() -> Vec<u8> {
        let pe_at = 0x80usize;
        let optional_size = 224usize;
        let mut bytes = vec![0u8; pe_at + 4 + 20 + optional_size + 40 + 0x200];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C..0x40].copy_from_slice(&(pe_at as u32).to_le_bytes());
        bytes[pe_at..pe_at + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_at + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());
        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        bytes[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        bytes[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // image base
        bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
        bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
        bytes[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        bytes[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        bytes[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // subsystem GUI
        bytes[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // data directory count
        let section = opt + optional_size;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        bytes[section + 20..section + 24].copy_from_slice(&((section + 40 + 0x200 - 0x200) as u32).to_le_bytes()); // raw pointer
        bytes
    }

    #[test]
    fn parses_a_minimal_elf_header_and_section_table() {
        let bytes = minimal_elf();
        let parser = ElfParser;
        assert!(parser.looks_like(&bytes));
        let finding = parser.parse(&bytes, 1000).expect("ELF parses");
        assert_eq!(finding.category, Category::Executable);
        assert!(finding.detail.contains("64-bit LSB"), "{}", finding.detail);
        assert!(finding.detail.contains("x86-64") || finding.detail.contains("X86_64"), "{}", finding.detail);
        assert_eq!(finding.fields[0].offset, 1000);
        let section_table = finding.fields.iter().find(|f| f.name == "Section headers").expect("section headers");
        assert_eq!(section_table.offset, 1064);
        assert_eq!(section_table.children.len(), 1);
        assert_eq!(finding.len, 128);
    }

    #[test]
    fn parses_a_minimal_pe_with_one_section() {
        let bytes = minimal_pe();
        let parser = PeParser;
        assert!(parser.looks_like(&bytes));
        assert!(!parser.looks_like(b"MZ not a pe"));
        let finding = parser.parse(&bytes, 0).expect("PE parses");
        assert!(finding.detail.contains("PE 32-bit"), "{}", finding.detail);
        assert!(finding.detail.contains("x86"), "{}", finding.detail);
        let sections = finding.fields.iter().find(|f| f.name == "Sections").expect("sections");
        assert_eq!(sections.children[0].name, ".text");
        assert_eq!(finding.len, bytes.len());
    }

    #[test]
    fn parses_the_running_test_binary_as_mach_o() {
        let path = std::env::current_exe().unwrap();
        let bytes = std::fs::read(path).unwrap();
        let parser = MachOParser;
        if !parser.looks_like(&bytes) {
            // Not on macOS: nothing to check here.
            return;
        }
        let finding = parser.parse(&bytes, 0).expect("Mach-O parses");
        assert_eq!(finding.category, Category::Executable);
        let commands = finding.fields.iter().find(|f| f.name == "Load commands").expect("load commands");
        assert!(!commands.children.is_empty());
        assert!(commands.children.iter().any(|c| c.name.contains("Segment")), "{:?}", commands.children.iter().map(|c| &c.name).collect::<Vec<_>>());
        let segments = finding.fields.iter().find(|f| f.name == "Segments").expect("segments");
        assert!(segments.children.iter().any(|s| s.name == "__TEXT"));
        assert!(finding.len > 1024);
    }

    #[test]
    fn java_class_files_are_not_fat_binaries() {
        let class = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41];
        assert!(!MachOParser.looks_like(&class));
        let fat = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        assert!(MachOParser.looks_like(&fat));
    }
}
