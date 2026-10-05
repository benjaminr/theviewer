//! Guessing the number type and byte order of a field in fixed-size records.
//!
//! The same four bytes can be an unsigned or signed integer in either byte
//! order, a float, a fixed-point number or one of several timestamp formats.
//! Read the field from every record under each interpretation and judge how
//! plausible the resulting column of values is:
//!
//! * integers should use few of their bits (small span) and change smoothly;
//! * floats should be finite, of sane magnitude and change gradually;
//! * timestamps should fall between 1990 and 2040, ideally in order.
//!
//! The wrong byte order turns a small, smooth column into large, jumpy
//! values, which is what separates LE from BE.

use std::fmt;

/// Most records read for one field.
const MAX_RECORDS: usize = 4096;
/// Sample values shown per interpretation.
const SAMPLES: usize = 5;
/// Earliest and latest plausible timestamps (Unix seconds): 1990-01-01 and 2040-01-01.
const EARLIEST_TIMESTAMP: f64 = 631_152_000.0;
const LATEST_TIMESTAMP: f64 = 2_208_988_800.0;
/// Seconds from the Unix epoch to other epochs.
const GPS_EPOCH_UNIX: f64 = 315_964_800.0;
const HFS_EPOCH_UNIX: f64 = -2_082_844_800.0;
const FILETIME_EPOCH_UNIX: f64 = -11_644_473_600.0;
/// FILETIME ticks (100 ns) per second.
const FILETIME_TICKS_PER_SECOND: f64 = 10_000_000.0;
/// Magnitudes a float is plausibly holding (zero aside).
const SMALLEST_SANE_FLOAT: f64 = 1e-6;
const LARGEST_SANE_FLOAT: f64 = 1e9;
/// A family must explain at least this fraction of records to score well.
const REQUIRED_FRACTION: f64 = 0.9;
/// Ceiling for plain integers, so a convincing timestamp or float outranks them.
const INTEGER_CEILING: f64 = 0.8;

/// What a field's bytes represent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NumberKind {
    Unsigned,
    Signed,
    Float,
    /// Signed fixed point with half the bits as fraction (Q8.8, Q16.16).
    FixedPoint,
    UnixSeconds,
    UnixMillis,
    /// Windows FILETIME: 100 ns ticks since 1601.
    FileTime,
    /// GPS seconds since 1980-01-06 (leap seconds ignored).
    GpsSeconds,
    /// Classic Mac / HFS seconds since 1904.
    HfsSeconds,
    /// MS-DOS / FAT time (low 16 bits) and date (high 16 bits).
    DosDateTime,
}

impl NumberKind {
    fn is_timestamp(self) -> bool {
        matches!(self, NumberKind::UnixSeconds | NumberKind::UnixMillis | NumberKind::FileTime | NumberKind::GpsSeconds | NumberKind::HfsSeconds | NumberKind::DosDateTime)
    }

    /// Prior belief in the kind, breaking ties between epochs that overlap
    /// (a Unix time read as GPS lands ten years later, still in range).
    fn prior(self) -> f64 {
        match self {
            NumberKind::GpsSeconds | NumberKind::HfsSeconds => 0.97,
            NumberKind::DosDateTime => 0.99,
            NumberKind::FixedPoint => 0.9,
            _ => 1.0,
        }
    }
}

/// One way of reading a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Interpretation {
    pub kind: NumberKind,
    /// Bytes: 1, 2, 4 or 8.
    pub width: usize,
    pub little_endian: bool,
}

impl Interpretation {
    /// A short name such as "u32 LE" or "Unix seconds (u32 BE)".
    pub fn label(&self) -> String {
        let bits = self.width * 8;
        let order = if self.width == 1 { "" } else if self.little_endian { " LE" } else { " BE" };
        match self.kind {
            NumberKind::Unsigned => format!("u{bits}{order}"),
            NumberKind::Signed => format!("i{bits}{order}"),
            NumberKind::Float => format!("f{bits}{order}"),
            NumberKind::FixedPoint => format!("Q{}.{}{order}", bits / 2, bits / 2),
            NumberKind::UnixSeconds => format!("Unix seconds (u{bits}{order})"),
            NumberKind::UnixMillis => format!("Unix milliseconds (u{bits}{order})"),
            NumberKind::FileTime => format!("Windows FILETIME (u{bits}{order})"),
            NumberKind::GpsSeconds => format!("GPS seconds (u{bits}{order})"),
            NumberKind::HfsSeconds => format!("Mac HFS seconds (u{bits}{order})"),
            NumberKind::DosDateTime => format!("DOS date-time ({bits}-bit{order})"),
        }
    }

    /// The value of `bytes` (exactly `width` long). Timestamps come back as
    /// Unix seconds. `None` for NaN, infinities and impossible dates.
    pub fn decode(&self, bytes: &[u8]) -> Option<f64> {
        if bytes.len() != self.width {
            return None;
        }
        let raw = read_unsigned(bytes, self.little_endian);
        let value = match self.kind {
            NumberKind::Unsigned => raw as f64,
            NumberKind::Signed => sign_extend(raw, self.width) as f64,
            NumberKind::Float => match self.width {
                4 => f64::from(f32::from_bits(raw as u32)),
                8 => f64::from_bits(raw),
                _ => return None,
            },
            NumberKind::FixedPoint => sign_extend(raw, self.width) as f64 / (1u64 << (self.width * 4)) as f64,
            NumberKind::UnixSeconds => raw as f64,
            NumberKind::UnixMillis => raw as f64 / 1000.0,
            NumberKind::FileTime => raw as f64 / FILETIME_TICKS_PER_SECOND + FILETIME_EPOCH_UNIX,
            NumberKind::GpsSeconds => raw as f64 + GPS_EPOCH_UNIX,
            NumberKind::HfsSeconds => raw as f64 + HFS_EPOCH_UNIX,
            NumberKind::DosDateTime => dos_date_time_to_unix(raw as u32)?,
        };
        value.is_finite().then_some(value)
    }

    /// The value of `bytes` formatted for the user.
    pub fn display(&self, bytes: &[u8]) -> String {
        let Some(value) = self.decode(bytes) else { return "invalid".to_string() };
        match self.kind {
            NumberKind::Unsigned | NumberKind::Signed => format!("{value:.0}"),
            NumberKind::Float | NumberKind::FixedPoint => format!("{value}"),
            _ if (0.0..=u64::MAX as f64).contains(&value) => crate::patterns::format_unix_seconds(value as u64),
            _ => format!("{value:.0} s before 1970"),
        }
    }
}

/// Read up to eight bytes as an unsigned integer.
fn read_unsigned(bytes: &[u8], little_endian: bool) -> u64 {
    let fold = |value: u64, &byte: &u8| (value << 8) | u64::from(byte);
    if little_endian { bytes.iter().rev().fold(0, fold) } else { bytes.iter().fold(0, fold) }
}

fn sign_extend(raw: u64, width: usize) -> i64 {
    let unused = 64 - width as u32 * 8;
    ((raw << unused) as i64) >> unused
}

/// Decode a FAT date-time (time in the low 16 bits, date in the high 16).
fn dos_date_time_to_unix(raw: u32) -> Option<f64> {
    const DOS_EPOCH_YEAR: i64 = 1980;
    let (date, time) = (raw >> 16, raw & 0xFFFF);
    let year = DOS_EPOCH_YEAR + i64::from(date >> 9);
    let month = (date >> 5) & 0x0F;
    let day = date & 0x1F;
    let hour = time >> 11;
    let minute = (time >> 5) & 0x3F;
    let second = (time & 0x1F) * 2;
    let valid = (1..=12).contains(&month) && (1..=31).contains(&day) && hour <= 23 && minute <= 59 && second <= 59;
    if !valid {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some((days * 86_400 + i64::from(hour * 3600 + minute * 60 + second)) as f64)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_index = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Every interpretation that applies to a field `width` bytes wide.
pub fn interpretations(width: usize) -> Vec<Interpretation> {
    let kinds: &[NumberKind] = match width {
        1 => &[NumberKind::Unsigned, NumberKind::Signed],
        2 => &[NumberKind::Unsigned, NumberKind::Signed, NumberKind::FixedPoint],
        4 => &[
            NumberKind::Unsigned,
            NumberKind::Signed,
            NumberKind::Float,
            NumberKind::FixedPoint,
            NumberKind::UnixSeconds,
            NumberKind::GpsSeconds,
            NumberKind::HfsSeconds,
            NumberKind::DosDateTime,
        ],
        8 => &[NumberKind::Unsigned, NumberKind::Signed, NumberKind::Float, NumberKind::UnixSeconds, NumberKind::UnixMillis, NumberKind::FileTime],
        _ => &[],
    };
    let orders: &[bool] = if width == 1 { &[true] } else { &[true, false] };
    kinds
        .iter()
        .flat_map(|&kind| orders.iter().map(move |&little_endian| Interpretation { kind, width, little_endian }))
        .collect()
}

/// Why a field could not be analysed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldError {
    /// Only 1, 2, 4 and 8 byte fields are supported.
    UnsupportedWidth(usize),
    /// The field does not fit inside the record.
    OutsideRecord { offset: usize, width: usize, record_len: usize },
    /// Fewer bytes than one record.
    NoRecords,
}

impl fmt::Display for FieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldError::UnsupportedWidth(width) => write!(formatter, "a field of {width} bytes is not supported; use 1, 2, 4 or 8"),
            FieldError::OutsideRecord { offset, width, record_len } => {
                write!(formatter, "a {width}-byte field at offset {offset} does not fit in a {record_len}-byte record")
            }
            FieldError::NoRecords => write!(formatter, "there is not a single whole record to read"),
        }
    }
}

impl std::error::Error for FieldError {}

/// One interpretation with its plausibility.
#[derive(Clone, Debug, PartialEq)]
pub struct RankedInterpretation {
    pub interpretation: Interpretation,
    /// Plausibility, 0..1.
    pub score: f64,
    /// Why it scored as it did, in a few words.
    pub reason: String,
    /// The first few records' values, formatted.
    pub samples: Vec<String>,
}

/// Rank every interpretation of the `width`-byte field at `offset` within
/// records of `record_len` bytes, most plausible first.
pub fn rank_field(records: &[u8], record_len: usize, offset: usize, width: usize) -> Result<Vec<RankedInterpretation>, FieldError> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err(FieldError::UnsupportedWidth(width));
    }
    if record_len == 0 || offset + width > record_len {
        return Err(FieldError::OutsideRecord { offset, width, record_len });
    }
    let fields: Vec<&[u8]> = records.chunks_exact(record_len).take(MAX_RECORDS).map(|record| &record[offset..offset + width]).collect();
    if fields.is_empty() {
        return Err(FieldError::NoRecords);
    }
    let mut ranked: Vec<RankedInterpretation> = interpretations(width)
        .into_iter()
        .map(|interpretation| {
            let values: Vec<Option<f64>> = fields.iter().map(|field| interpretation.decode(field)).collect();
            let (score, reason) = score_values(interpretation, &values);
            let samples = fields.iter().take(SAMPLES).map(|field| interpretation.display(field)).collect();
            RankedInterpretation { interpretation, score: score * interpretation.kind.prior(), reason, samples }
        })
        .collect();
    // Stable, so on a tie unsigned beats signed and little endian beats big.
    ranked.sort_by(|a, b| b.score.total_cmp(&a.score));
    Ok(ranked)
}

/// Summary statistics of a column of decoded values.
struct ColumnShape {
    valid_fraction: f64,
    span: f64,
    /// 1 when neighbouring records hold close values, towards 0 when they jump.
    smoothness: f64,
    /// Fraction of neighbouring pairs that do not decrease.
    rising_fraction: f64,
}

fn column_shape(values: &[Option<f64>]) -> ColumnShape {
    let valid: Vec<f64> = values.iter().flatten().copied().collect();
    let valid_fraction = valid.len() as f64 / values.len().max(1) as f64;
    let (min, max) = valid.iter().fold((f64::INFINITY, f64::NEG_INFINITY), |(min, max), &v| (min.min(v), max.max(v)));
    let span = if valid.is_empty() { 0.0 } else { max - min };
    let steps: Vec<f64> = valid.windows(2).map(|pair| pair[1] - pair[0]).collect();
    let rising_fraction = if steps.is_empty() { 1.0 } else { steps.iter().filter(|&&step| step >= 0.0).count() as f64 / steps.len() as f64 };
    let typical_step = median(steps.iter().map(|step| step.abs()).collect());
    let smoothness = if span <= 0.0 { 1.0 } else { 1.0 - (typical_step / span).min(1.0) };
    ColumnShape { valid_fraction, span, smoothness, rising_fraction }
}

fn median(mut values: Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

/// Score a column of values under one interpretation, with a reason.
fn score_values(interpretation: Interpretation, values: &[Option<f64>]) -> (f64, String) {
    let shape = column_shape(values);
    match interpretation.kind {
        NumberKind::Unsigned | NumberKind::Signed | NumberKind::FixedPoint => score_integer(interpretation, &shape),
        NumberKind::Float => score_float(values, &shape),
        kind if kind.is_timestamp() => score_timestamp(values, &shape),
        _ => (0.0, String::new()),
    }
}

fn score_integer(interpretation: Interpretation, shape: &ColumnShape) -> (f64, String) {
    const COMPACTNESS_WEIGHT: f64 = 0.6;
    let bits = (interpretation.width * 8) as f64;
    // Fixed point spreads the same integers over a smaller scale; measure in raw units.
    let raw_span = if interpretation.kind == NumberKind::FixedPoint { shape.span * (1u64 << (interpretation.width * 4)) as f64 } else { shape.span };
    let bits_used = (raw_span + 1.0).log2();
    let compactness = (1.0 - bits_used / bits).clamp(0.0, 1.0);
    let score = INTEGER_CEILING * (COMPACTNESS_WEIGHT * compactness + (1.0 - COMPACTNESS_WEIGHT) * shape.smoothness);
    (score, format!("values span {bits_used:.0} of {bits:.0} bits, smoothness {:.2}", shape.smoothness))
}

fn score_float(values: &[Option<f64>], shape: &ColumnShape) -> (f64, String) {
    const FLOOR: f64 = 0.6;
    const RANGE: f64 = 0.35;
    const ALL_ZERO_SCORE: f64 = 0.3;
    let valid: Vec<f64> = values.iter().flatten().copied().collect();
    let sane = valid.iter().filter(|v| **v == 0.0 || (SMALLEST_SANE_FLOAT..=LARGEST_SANE_FLOAT).contains(&v.abs())).count();
    let sane_fraction = sane as f64 / values.len().max(1) as f64;
    if sane_fraction < REQUIRED_FRACTION {
        return (0.2 * sane_fraction, format!("only {:.0}% finite and of sane magnitude", sane_fraction * 100.0));
    }
    if valid.iter().all(|&v| v == 0.0) {
        return (ALL_ZERO_SCORE, "all zero".to_string());
    }
    let typical_magnitude = median(valid.iter().map(|v| v.abs()).collect());
    let typical_step = median(valid.windows(2).map(|pair| (pair[1] - pair[0]).abs()).collect());
    let gradual = 1.0 - (typical_step / (typical_magnitude + f64::EPSILON)).min(1.0);
    let score = FLOOR + RANGE * (0.5 * gradual + 0.5 * shape.smoothness);
    (score, format!("{:.0}% sane floats, typical magnitude {typical_magnitude:.3e}", sane_fraction * 100.0))
}

fn score_timestamp(values: &[Option<f64>], shape: &ColumnShape) -> (f64, String) {
    // Order weighs most: real timestamp columns mostly rise, and it separates
    // them from floats whose bits happen to read as 2004–2011 dates.
    const FLOOR: f64 = 0.82;
    const SMOOTHNESS_WEIGHT: f64 = 0.05;
    const ORDER_WEIGHT: f64 = 0.13;
    let in_range = values.iter().flatten().filter(|v| (EARLIEST_TIMESTAMP..=LATEST_TIMESTAMP).contains(*v)).count();
    let in_range_fraction = in_range as f64 / values.len().max(1) as f64;
    if in_range_fraction < REQUIRED_FRACTION {
        return (0.3 * in_range_fraction, format!("only {:.0}% between 1990 and 2040", in_range_fraction * 100.0));
    }
    let score = FLOOR + SMOOTHNESS_WEIGHT * shape.smoothness + ORDER_WEIGHT * shape.rising_fraction;
    let reason = format!("{:.0}% between 1990 and 2040, {:.0}% in order", in_range_fraction * 100.0, shape.rising_fraction * 100.0 * shape.valid_fraction);
    (score, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records of `record_len` bytes with `field` written at `offset`.
    fn records_with(record_len: usize, offset: usize, fields: &[Vec<u8>]) -> Vec<u8> {
        let mut data = Vec::new();
        for (index, field) in fields.iter().enumerate() {
            let mut record = vec![(index % 7) as u8; record_len];
            record[offset..offset + field.len()].copy_from_slice(field);
            data.extend(record);
        }
        data
    }

    fn best(data: &[u8], record_len: usize, offset: usize, width: usize) -> String {
        rank_field(data, record_len, offset, width).expect("ranked")[0].interpretation.label()
    }

    #[test]
    fn a_u32_le_unix_timestamp_column_ranks_unix_seconds_first() {
        let fields: Vec<Vec<u8>> = (0..200u32).map(|index| (1_700_000_000 + index * 61).to_le_bytes().to_vec()).collect();
        let data = records_with(16, 4, &fields);
        assert_eq!(best(&data, 16, 4, 4), "Unix seconds (u32 LE)");
    }

    #[test]
    fn a_small_big_endian_counter_ranks_u16_be_first() {
        let fields: Vec<Vec<u8>> = (0..300u16).map(|index| (index * 3).to_be_bytes().to_vec()).collect();
        let data = records_with(8, 2, &fields);
        assert_eq!(best(&data, 8, 2, 2), "u16 BE");
    }

    #[test]
    fn a_column_of_measurements_ranks_as_f32() {
        let fields: Vec<Vec<u8>> = (0..200).map(|index| (20.0f32 + (index as f32 * 0.05).sin()).to_le_bytes().to_vec()).collect();
        let data = records_with(12, 0, &fields);
        assert_eq!(best(&data, 12, 0, 4), "f32 LE");
    }

    #[test]
    fn small_negative_numbers_rank_as_signed() {
        let fields: Vec<Vec<u8>> = (0..200i32).map(|index| (index % 21 - 10).to_le_bytes().to_vec()).collect();
        let data = records_with(4, 0, &fields);
        assert_eq!(best(&data, 4, 0, 4), "i32 LE");
    }

    #[test]
    fn filetime_and_dos_timestamps_decode_to_the_right_date() {
        // 2024-01-01 00:00:00 UTC.
        let unix = 1_704_067_200u64;
        let filetime = (unix + 11_644_473_600) * 10_000_000;
        let interpretation = Interpretation { kind: NumberKind::FileTime, width: 8, little_endian: true };
        assert_eq!(interpretation.display(&filetime.to_le_bytes()), "2024-01-01 00:00:00 UTC");
        // DOS: date 2024-01-01 = (44 << 9) | (1 << 5) | 1, time 00:00:00.
        let dos = ((44u32 << 9 | 1 << 5 | 1) << 16).to_le_bytes();
        let dos_reading = Interpretation { kind: NumberKind::DosDateTime, width: 4, little_endian: true };
        assert_eq!(dos_reading.decode(&dos), Some(unix as f64));
    }

    #[test]
    fn a_filetime_column_ranks_filetime_first() {
        let fields: Vec<Vec<u8>> = (0..100u64).map(|index| ((1_600_000_000 + index * 3600 + 11_644_473_600) * 10_000_000).to_le_bytes().to_vec()).collect();
        let data = records_with(24, 8, &fields);
        assert_eq!(best(&data, 24, 8, 8), "Windows FILETIME (u64 LE)");
    }

    #[test]
    fn invalid_fields_are_explained() {
        assert_eq!(rank_field(&[0; 16], 8, 0, 3), Err(FieldError::UnsupportedWidth(3)));
        assert_eq!(rank_field(&[0; 16], 8, 6, 4), Err(FieldError::OutsideRecord { offset: 6, width: 4, record_len: 8 }));
        assert_eq!(rank_field(&[0; 4], 8, 0, 4), Err(FieldError::NoRecords));
        assert!(FieldError::NoRecords.to_string().contains("record"));
    }

    #[test]
    fn samples_show_the_first_records() {
        let fields: Vec<Vec<u8>> = (0..10u8).map(|index| vec![index]).collect();
        let data = records_with(2, 1, &fields);
        let ranked = rank_field(&data, 2, 1, 1).expect("ranked");
        let unsigned = ranked.iter().find(|r| r.interpretation.kind == NumberKind::Unsigned).expect("u8 listed");
        assert_eq!(unsigned.samples, vec!["0", "1", "2", "3", "4"]);
    }
}
