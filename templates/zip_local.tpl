// ZIP local file entries. The array stops at the first entry whose
// signature does not match, which is where the central directory begins.
endian little

struct LocalFile {
    signature: u32 = 0x04034b50 display hex
    version_needed: u16
    flags: u16 display hex
    method: u16 enum { 0 = "stored", 8 = "deflate", 9 = "deflate64", 12 = "bzip2", 14 = "lzma", 93 = "zstd", 95 = "xz" }
    modified_time: u16
    modified_date: u16
    crc32: u32 display hex
    compressed_size: u32
    uncompressed_size: u32
    name_len: u16
    extra_len: u16
    name: char[name_len]
    extra: bytes[extra_len]
    data: bytes[compressed_size]
}

root LocalFile[until_end]
