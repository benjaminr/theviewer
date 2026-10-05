// PNG: the eight-byte signature, then length-prefixed chunks.
endian big

struct Chunk {
    len: u32
    type: char[4]
    data: bytes[len]
    crc: u32 display hex
}

struct Png {
    signature: bytes[8] = "\x89PNG\r\n\x1a\n"
    chunks: Chunk[until_end]
}

root Png
