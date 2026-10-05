// A generic table of fixed-size records. Edit the fields to match your
// data; "Infer from selection" can write a first draft for you.
endian little

struct Record {
    id: u32
    timestamp: u32
    value: f32
    flags: u16 display hex
    name: char[10]
}

root Record[until_end]
