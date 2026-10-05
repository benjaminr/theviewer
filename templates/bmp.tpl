// Windows bitmap: file header, BITMAPINFOHEADER, then the pixel data.
endian little

struct FileHeader {
    magic: char[2] = "BM"
    size: u32
    reserved_1: u16
    reserved_2: u16
    data_offset: u32 display hex
}

struct InfoHeader {
    header_size: u32
    width: i32
    height: i32               // negative means top-down rows
    planes: u16 = 1
    bits_per_pixel: u16
    compression: u32 enum { 0 = "BI_RGB", 1 = "BI_RLE8", 2 = "BI_RLE4", 3 = "BI_BITFIELDS", 6 = "BI_ALPHABITFIELDS" }
    image_size: u32           // may be 0 for uncompressed images
    x_pixels_per_metre: i32
    y_pixels_per_metre: i32
    colours_used: u32
    colours_important: u32
}

struct Bmp {
    file: FileHeader
    info: InfoHeader
    pixels: bytes[info.image_size] @ file.data_offset
}

root Bmp
