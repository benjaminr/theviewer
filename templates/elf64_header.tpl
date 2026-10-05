// 64-bit little-endian ELF header and its program headers.
endian little

struct Ident {
    magic: bytes[4] = "\x7fELF"
    class: u8 enum { 1 = "32-bit", 2 = "64-bit" }
    data: u8 enum { 1 = "little endian", 2 = "big endian" }
    version: u8
    os_abi: u8 enum { 0 = "System V", 3 = "Linux", 9 = "FreeBSD", 12 = "OpenBSD" }
    abi_version: u8
    padding: bytes[7]
}

struct ProgramHeader {
    type: u32 enum { 0 = "NULL", 1 = "LOAD", 2 = "DYNAMIC", 3 = "INTERP", 4 = "NOTE", 6 = "PHDR", 7 = "TLS" }
    flags: u32 display hex
    offset: u64 display hex
    virtual_address: u64 display hex
    physical_address: u64 display hex
    file_size: u64
    memory_size: u64
    align: u64 display hex
}

struct Elf64Header {
    ident: Ident
    type: u16 enum { 1 = "relocatable", 2 = "executable", 3 = "shared object", 4 = "core" }
    machine: u16 enum { 3 = "x86", 40 = "ARM", 62 = "x86-64", 183 = "AArch64", 243 = "RISC-V" }
    version: u32
    entry: u64 display hex
    program_header_offset: u64 display hex
    section_header_offset: u64 display hex
    flags: u32 display hex
    header_size: u16
    program_header_size: u16
    program_header_count: u16
    section_header_size: u16
    section_header_count: u16
    section_names_index: u16
    program_headers: ProgramHeader[program_header_count] @ program_header_offset
}

root Elf64Header
