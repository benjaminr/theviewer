// RIFF container (WAV, AVI, WebP): a header, then chunks until the end.
endian little

struct Header {
    magic: char[4] = "RIFF"
    size: u32
    kind: char[4]
}

struct Chunk {
    id: char[4]
    len: u32
    data: bytes[len]
    pad: bytes[len % 2]        // chunks are padded to an even length
}

struct Riff {
    header: Header
    chunks: Chunk[until_end]
}

root Riff
