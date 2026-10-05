//! Finds well-known cryptographic and compression constants, in the spirit of
//! IDA's findcrypt: AES tables, hash initial values and round constants, CRC
//! tables, deflate base tables, Blowfish and DES tables, ChaCha/Salsa sigma
//! strings, elliptic-curve primes, RSA exponents and Base64 tables.
//!
//! Tables that can be derived (AES, CRC) are generated at start-up rather than
//! typed in, so a typo cannot hide a match. Multi-byte tables are searched in
//! both byte orders. Matching uses one Aho-Corasick automaton over every
//! pattern; a few patterns (RSA exponent, Base64) are verified afterwards.
//!
//! [`CryptoConstantDetector`] exposes the scanner through the plugin API, and
//! [`scan_constants`] returns richer [`CryptoMatch`]es for the Crypto panel.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::plugin::{Category, Detector, Finding, ScanContext};

/// Identifier of the detector in the plugin registry.
pub const DETECTOR_ID: &str = "builtin.crypto";
/// Prefix of every finding id this detector produces.
const FINDING_ID_PREFIX: &str = "crypto";
/// Most matches reported from one window, so pathological input stays bounded.
const MAX_MATCHES_PER_SCAN: usize = 4096;
/// How many leading entries of a word table are searched for.
const TABLE_PREFIX_ENTRIES: usize = 16;
/// How far back from an RSA exponent we look for the DER modulus header.
const MAX_RSA_MODULUS_BYTES: usize = 1032;
/// Bytes a caller scanning in chunks should overlap consecutive windows by,
/// so no constant (or RSA lookback) is cut in half.
pub const RECOMMENDED_OVERLAP: usize = 4096;

/// Confidence for matches that verify a surrounding structure or span a long table.
const CONFIDENCE_LONG: f32 = 0.95;
/// Confidence for matches of 16 to 31 bytes.
const CONFIDENCE_MEDIUM: f32 = 0.85;
/// Confidence for matches of 8 to 15 bytes.
const CONFIDENCE_SHORT: f32 = 0.6;
/// Confidence for very short constants that also occur by coincidence.
const CONFIDENCE_WEAK: f32 = 0.3;

/// DER encoding of the INTEGER 65537 (the common RSA public exponent).
const DER_EXPONENT_65537: [u8; 5] = [0x02, 0x03, 0x01, 0x00, 0x01];
/// DER tag of an INTEGER.
const DER_INTEGER: u8 = 0x02;
/// DER long-form length marker: one length byte follows.
const DER_LENGTH_ONE_BYTE: u8 = 0x81;
/// DER long-form length marker: two length bytes follow.
const DER_LENGTH_TWO_BYTES: u8 = 0x82;

/// The 62 letters and digits shared by every Base64 alphabet.
const BASE64_CORE: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Decoded values of '0' to '9' (52..=61), the anchor of a Base64 decoding table.
const BASE64_DIGIT_VALUES: [u8; 10] = [52, 53, 54, 55, 56, 57, 58, 59, 60, 61];
/// Smallest decoding table we report: indices up to and including 'z'.
const BASE64_DECODE_TABLE_MIN_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Literal constants (those that cannot be cheaply derived)
// ---------------------------------------------------------------------------

/// MD5 (and MD4, RIPEMD-128) initial chaining values.
const MD5_INITIAL: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];
/// The first four MD5 sine-derived round constants.
const MD5_SINE_PREFIX: [u32; 4] = [0xD76A_A478, 0xE8C7_B756, 0x2420_70DB, 0xC1BD_CEEE];
/// SHA-1 (and RIPEMD-160) initial chaining values.
const SHA1_INITIAL: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
/// SHA-224 initial chaining values.
const SHA224_INITIAL: [u32; 8] = [
    0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939, 0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEFA_4FA4,
];
/// SHA-256 initial chaining values.
const SHA256_INITIAL: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
];
/// The first sixteen SHA-256 round constants.
const SHA256_ROUND_PREFIX: [u32; 16] = [
    0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5, 0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5,
    0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3, 0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174,
];
/// SHA-384 initial chaining values (first four of eight).
const SHA384_INITIAL_PREFIX: [u64; 4] = [
    0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507, 0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939,
];
/// SHA-512 initial chaining values.
const SHA512_INITIAL: [u64; 8] = [
    0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
];
/// The first four SHA-512 round constants.
const SHA512_ROUND_PREFIX: [u64; 4] = [
    0x428A_2F98_D728_AE22, 0x7137_4491_23EF_65CD, 0xB5C0_FBCF_EC4D_3B2F, 0xE9B5_DBA5_8189_DBBC,
];
/// The first eight words of the Blowfish P-array (hex digits of pi).
const BLOWFISH_P_PREFIX: [u32; 8] = [
    0x243F_6A88, 0x85A3_08D3, 0x1319_8A2E, 0x0370_7344, 0xA409_3822, 0x299F_31D0, 0x082E_FA98, 0xEC4E_6C89,
];
/// The first four words of Blowfish S-box 0.
const BLOWFISH_S0_PREFIX: [u32; 4] = [0xD131_0BA6, 0x98DF_B5AC, 0x2FFD_72DB, 0xD01A_DFB7];
/// DES S-box 1, four rows of sixteen.
const DES_SBOX1: [u8; 64] = [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, //
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, //
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, //
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
];
/// The first sixteen entries of the DES permuted choice 1 (1-based bit numbers).
const DES_PC1_PREFIX: [u8; 16] = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2];
/// The first eight entries of the combined S-box/permutation table SP1 used by
/// fast DES implementations (Outerbridge's d3des and descendants).
const DES_SP1_PREFIX: [u32; 8] = [
    0x0101_0400, 0x0000_0000, 0x0001_0000, 0x0101_0404, 0x0101_0004, 0x0001_0404, 0x0000_0004, 0x0001_0000,
];
/// Deflate length codes 257..285: base match lengths.
const DEFLATE_LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
];
/// Deflate distance codes 0..29: base distances.
const DEFLATE_DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
/// AES key-schedule round constants as bytes.
const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
/// TEA/XTEA key schedule constant (2^32 divided by the golden ratio).
const TEA_DELTA: u32 = 0x9E37_79B9;
/// TEA decryption's starting sum: the delta times 32 rounds.
const TEA_DECRYPT_SUM: u32 = 0xC6EF_3720;
/// The NIST P-256 field prime, big-endian.
const P256_PRIME: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];
/// The x coordinate of the NIST P-256 base point, big-endian.
const P256_GENERATOR_X: [u8; 32] = [
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, //
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
];

/// CRC-32 (IEEE 802.3) polynomial, normal form.
const CRC32_POLYNOMIAL: u32 = 0x04C1_1DB7;
/// CRC-32 (IEEE 802.3) polynomial, reflected form.
const CRC32_POLYNOMIAL_REFLECTED: u32 = 0xEDB8_8320;
/// CRC-32C (Castagnoli) polynomial, reflected form.
const CRC32C_POLYNOMIAL_REFLECTED: u32 = 0x82F6_3B78;
/// CRC-16-CCITT polynomial, normal form (XMODEM, CCITT-FALSE).
const CRC16_CCITT_POLYNOMIAL: u16 = 0x1021;
/// CRC-16-CCITT polynomial, reflected form (Kermit, X.25).
const CRC16_CCITT_POLYNOMIAL_REFLECTED: u16 = 0x8408;
/// CRC-16/ARC (IBM, Modbus) polynomial, reflected form.
const CRC16_ARC_POLYNOMIAL_REFLECTED: u16 = 0xA001;
/// The AES field's reduction polynomial x^8 + x^4 + x^3 + x + 1, less x^8.
const AES_REDUCTION: u8 = 0x1B;
/// The constant added by the AES S-box affine transform.
const AES_AFFINE_CONSTANT: u8 = 0x63;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One constant found in the bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct CryptoMatch {
    /// Algorithm family, e.g. "AES" or "SHA-256", used to group results.
    pub algorithm: &'static str,
    /// Which table or value, e.g. "S-box" or "initial values".
    pub table: String,
    /// Byte order of the stored words, or empty for byte tables and strings.
    pub byte_order: &'static str,
    /// Document offset of the first byte.
    pub start: usize,
    pub len: usize,
    /// 0 to 1; long tables and verified structures score highest.
    pub confidence: f32,
    /// Extra explanation, such as which other algorithms share the constant.
    pub note: String,
}

impl CryptoMatch {
    /// Short label such as "AES S-box".
    pub fn title(&self) -> String {
        format!("{} {}", self.algorithm, self.table)
    }

    /// Byte order and note joined for tooltips.
    pub fn detail(&self) -> String {
        let mut parts = Vec::new();
        if !self.byte_order.is_empty() {
            parts.push(self.byte_order.to_string());
        }
        parts.push(format!("{} bytes", self.len));
        if !self.note.is_empty() {
            parts.push(self.note.clone());
        }
        parts.join(", ")
    }

    /// Stable finding id, e.g. `crypto:aes`.
    pub fn finding_id(&self) -> String {
        let slug: String = self
            .algorithm
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
            .collect();
        format!("{FINDING_ID_PREFIX}:{slug}")
    }

    /// The match as a plugin finding.
    pub fn to_finding(&self) -> Finding {
        Finding::new(self.finding_id(), DETECTOR_ID, Category::Encoding, self.start, self.len)
            .title(self.title())
            .detail(self.detail())
            .confidence(self.confidence)
    }
}

/// Plugin detector reporting crypto and compression constants as
/// [`Category::Encoding`] findings.
#[derive(Clone, Copy, Debug, Default)]
pub struct CryptoConstantDetector;

impl Detector for CryptoConstantDetector {
    fn id(&self) -> &str {
        DETECTOR_ID
    }

    fn name(&self) -> &str {
        "Crypto constants"
    }

    fn categories(&self) -> Vec<Category> {
        vec![Category::Encoding]
    }

    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        scan_constants(window, context.base).iter().map(CryptoMatch::to_finding).collect()
    }
}

/// Find every known constant in `bytes`, which start at document offset
/// `base`. Matches lying inside a longer match (an MD5 IV inside a SHA-1 IV)
/// are dropped. Results are ordered by offset.
pub fn scan_constants(bytes: &[u8], base: usize) -> Vec<CryptoMatch> {
    let catalogue = catalogue();
    let mut raw: Vec<CryptoMatch> = Vec::new();
    for found in catalogue.automaton.find_overlapping_iter(bytes) {
        if raw.len() >= MAX_MATCHES_PER_SCAN {
            break;
        }
        let constant = &catalogue.constants[found.pattern().as_usize()];
        if let Some(matched) = constant.confirm(bytes, found.start(), base) {
            raw.push(matched);
        }
    }
    drop_contained(raw)
}

// ---------------------------------------------------------------------------
// The catalogue of patterns
// ---------------------------------------------------------------------------

/// How a raw pattern hit is turned into a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verification {
    /// The pattern alone is the evidence.
    None,
    /// DER INTEGER 65537; look back for the modulus.
    RsaExponent,
    /// The 62 alphanumerics; read the last two characters to name the variant.
    Base64Alphabet,
    /// The decoded values of the digits; check the rest of the decoding table.
    Base64DecodeTable,
}

/// One searchable pattern.
struct Constant {
    algorithm: &'static str,
    table: String,
    byte_order: &'static str,
    bytes: Vec<u8>,
    confidence: f32,
    note: &'static str,
    verification: Verification,
}

impl Constant {
    fn plain(algorithm: &'static str, table: impl Into<String>, bytes: Vec<u8>) -> Self {
        let confidence = confidence_for_length(bytes.len());
        Constant {
            algorithm,
            table: table.into(),
            byte_order: "",
            bytes,
            confidence,
            note: "",
            verification: Verification::None,
        }
    }

    fn with_note(mut self, note: &'static str) -> Self {
        self.note = note;
        self
    }

    fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    fn verified_by(mut self, verification: Verification) -> Self {
        self.verification = verification;
        self
    }

    /// Turn a pattern hit at `at` into a match, or reject it.
    fn confirm(&self, bytes: &[u8], at: usize, base: usize) -> Option<CryptoMatch> {
        let plain = CryptoMatch {
            algorithm: self.algorithm,
            table: self.table.clone(),
            byte_order: self.byte_order,
            start: base + at,
            len: self.bytes.len(),
            confidence: self.confidence,
            note: self.note.to_string(),
        };
        match self.verification {
            Verification::None => Some(plain),
            Verification::RsaExponent => Some(confirm_rsa_exponent(bytes, at, plain)),
            Verification::Base64Alphabet => confirm_base64_alphabet(bytes, at, plain),
            Verification::Base64DecodeTable => confirm_base64_decode_table(bytes, at, base, plain),
        }
    }
}

/// Every pattern plus the automaton that finds them.
struct Catalogue {
    constants: Vec<Constant>,
    automaton: AhoCorasick,
}

fn catalogue() -> &'static Catalogue {
    static CATALOGUE: OnceLock<Catalogue> = OnceLock::new();
    CATALOGUE.get_or_init(|| {
        let constants = all_constants();
        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(constants.iter().map(|constant| &constant.bytes))
            .expect("the built-in crypto patterns are small and always build");
        Catalogue { constants, automaton }
    })
}

fn confidence_for_length(len: usize) -> f32 {
    match len {
        32.. => CONFIDENCE_LONG,
        16..=31 => CONFIDENCE_MEDIUM,
        8..=15 => CONFIDENCE_SHORT,
        _ => CONFIDENCE_WEAK,
    }
}

fn all_constants() -> Vec<Constant> {
    let mut constants = Vec::new();
    constants.extend(aes_constants());
    constants.extend(hash_constants());
    constants.extend(crc_constants());
    constants.extend(deflate_constants());
    constants.extend(cipher_constants());
    constants.extend(public_key_constants());
    constants.extend(base64_constants());
    constants
}

fn aes_constants() -> Vec<Constant> {
    let sbox = aes_sbox();
    let inverse = aes_inverse_sbox();
    let mut constants = vec![
        Constant::plain("AES", "S-box", sbox.to_vec()),
        Constant::plain("AES", "inverse S-box", inverse.to_vec()),
        Constant::plain("AES", "round constants", AES_RCON.to_vec()).with_confidence(CONFIDENCE_SHORT),
    ];
    let encrypt = aes_encryption_table();
    let decrypt = aes_decryption_table();
    for rotation in 0..4u32 {
        let te: Vec<u32> = encrypt.iter().take(TABLE_PREFIX_ENTRIES).map(|word| word.rotate_right(8 * rotation)).collect();
        let td: Vec<u32> = decrypt.iter().take(TABLE_PREFIX_ENTRIES).map(|word| word.rotate_right(8 * rotation)).collect();
        let note = "first 16 entries of the T-table";
        constants.extend(u32_words("AES", format!("Te{rotation} table"), &te, note));
        constants.extend(u32_words("AES", format!("Td{rotation} table"), &td, note));
    }
    constants
}

fn hash_constants() -> Vec<Constant> {
    let mut constants = Vec::new();
    constants.extend(u32_words("MD5", "initial values", &MD5_INITIAL, "shared with MD4 and RIPEMD-128"));
    constants.extend(u32_words("MD5", "sine constants", &MD5_SINE_PREFIX, "first four round constants"));
    constants.extend(u32_words("SHA-1", "initial values", &SHA1_INITIAL, "shared with RIPEMD-160"));
    constants.extend(u32_words("SHA-224", "initial values", &SHA224_INITIAL, ""));
    constants.extend(u32_words("SHA-256", "initial values", &SHA256_INITIAL, ""));
    constants.extend(u32_words("SHA-256", "round constants", &SHA256_ROUND_PREFIX, "first 16 of 64"));
    constants.extend(u64_words("SHA-384", "initial values", &SHA384_INITIAL_PREFIX, "first four of eight"));
    constants.extend(u64_words("SHA-512", "initial values", &SHA512_INITIAL, ""));
    constants.extend(u64_words("SHA-512", "round constants", &SHA512_ROUND_PREFIX, "first four of 80"));
    constants
}

fn crc_constants() -> Vec<Constant> {
    let note = "first 16 entries of the lookup table";
    let mut constants = Vec::new();
    let crc32 = |polynomial, reflected| -> Vec<u32> { crc32_table(polynomial, reflected).into_iter().take(TABLE_PREFIX_ENTRIES).collect() };
    let crc16 = |polynomial, reflected| -> Vec<u16> { crc16_table(polynomial, reflected).into_iter().take(TABLE_PREFIX_ENTRIES).collect() };
    constants.extend(u32_words("CRC-32", "table (normal, 0x04C11DB7)", &crc32(CRC32_POLYNOMIAL, false), note));
    constants.extend(u32_words("CRC-32", "table (reflected, 0xEDB88320)", &crc32(CRC32_POLYNOMIAL_REFLECTED, true), note));
    constants.extend(u32_words("CRC-32C", "table (reflected, 0x82F63B78)", &crc32(CRC32C_POLYNOMIAL_REFLECTED, true), note));
    constants.extend(u16_words("CRC-16", "CCITT table (normal, 0x1021)", &crc16(CRC16_CCITT_POLYNOMIAL, false), note));
    constants.extend(u16_words("CRC-16", "CCITT table (reflected, 0x8408)", &crc16(CRC16_CCITT_POLYNOMIAL_REFLECTED, true), note));
    constants.extend(u16_words("CRC-16", "ARC/Modbus table (reflected, 0xA001)", &crc16(CRC16_ARC_POLYNOMIAL_REFLECTED, true), note));
    constants
}

fn deflate_constants() -> Vec<Constant> {
    let widen = |values: &[u16]| -> Vec<u32> { values.iter().map(|&value| u32::from(value)).collect() };
    let mut constants = Vec::new();
    constants.extend(u16_words("Deflate", "length base table", &DEFLATE_LENGTH_BASE, "16-bit entries"));
    constants.extend(u16_words("Deflate", "distance base table", &DEFLATE_DISTANCE_BASE, "16-bit entries"));
    constants.extend(u32_words("Deflate", "length base table", &widen(&DEFLATE_LENGTH_BASE), "32-bit entries"));
    constants.extend(u32_words("Deflate", "distance base table", &widen(&DEFLATE_DISTANCE_BASE), "32-bit entries"));
    constants
}

fn cipher_constants() -> Vec<Constant> {
    let zero_based_pc1: Vec<u8> = DES_PC1_PREFIX.iter().map(|&bit| bit - 1).collect();
    let mut constants = vec![
        Constant::plain("DES", "S-box 1", DES_SBOX1.to_vec()),
        Constant::plain("DES", "PC-1 permutation", DES_PC1_PREFIX.to_vec()).with_note("1-based, first 16 entries"),
        Constant::plain("DES", "PC-1 permutation", zero_based_pc1).with_note("0-based, first 16 entries"),
        Constant::plain("ChaCha/Salsa20", "sigma constant", b"expand 32-byte k".to_vec()).with_note("256-bit key"),
        Constant::plain("ChaCha/Salsa20", "tau constant", b"expand 16-byte k".to_vec()).with_note("128-bit key"),
    ];
    constants.extend(u32_words("DES", "SP1 table", &DES_SP1_PREFIX, "combined S-box and permutation, first eight entries"));
    constants.extend(u32_words("Blowfish", "P-array", &BLOWFISH_P_PREFIX, "first eight words (digits of pi)"));
    constants.extend(u32_words("Blowfish", "S-box 0", &BLOWFISH_S0_PREFIX, "first four words"));
    let tea_note = "golden-ratio constant, also used by hash functions";
    for (table, value) in [("delta", TEA_DELTA), ("decryption sum", TEA_DECRYPT_SUM)] {
        constants.extend(u32_words("TEA/XTEA", table, &[value], tea_note).into_iter().map(|c| c.with_confidence(CONFIDENCE_WEAK)));
    }
    constants
}

fn public_key_constants() -> Vec<Constant> {
    let curve25519_prime_le = curve25519_prime_little_endian();
    let mut constants = vec![
        Constant::plain("RSA", "public exponent 65537", DER_EXPONENT_65537.to_vec())
            .with_note("DER INTEGER")
            .with_confidence(CONFIDENCE_WEAK)
            .verified_by(Verification::RsaExponent),
    ];
    constants.extend(byte_orders("Curve25519", "field prime 2^255 - 19", curve25519_prime_le, ""));
    constants.extend(byte_orders("P-256", "field prime", reversed(&P256_PRIME), ""));
    constants.extend(byte_orders("P-256", "base point x", reversed(&P256_GENERATOR_X), ""));
    constants
}

fn base64_constants() -> Vec<Constant> {
    vec![
        Constant::plain("Base64", "alphabet", BASE64_CORE.to_vec()).verified_by(Verification::Base64Alphabet),
        Constant::plain("Base64", "decoding table", BASE64_DIGIT_VALUES.to_vec()).verified_by(Verification::Base64DecodeTable),
    ]
}

// ---------------------------------------------------------------------------
// Byte-order helpers
// ---------------------------------------------------------------------------

/// Little- and big-endian patterns for one table, given its little-endian bytes.
/// A palindromic table yields one pattern.
fn byte_orders(algorithm: &'static str, table: impl Into<String>, little: Vec<u8>, note: &'static str) -> Vec<Constant> {
    let table = table.into();
    let big = reversed_words(&little, little.len());
    let mut little_constant = Constant::plain(algorithm, table.clone(), little).with_note(note);
    if big == little_constant.bytes {
        return vec![little_constant];
    }
    little_constant.byte_order = "little-endian";
    let mut big_constant = Constant::plain(algorithm, table, big).with_note(note);
    big_constant.byte_order = "big-endian";
    vec![little_constant, big_constant]
}

/// Patterns for a table of 16-bit words in both byte orders.
fn u16_words(algorithm: &'static str, table: impl Into<String>, words: &[u16], note: &'static str) -> Vec<Constant> {
    let little: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    word_orders(algorithm, table, little, size_of::<u16>(), note)
}

/// Patterns for a table of 32-bit words in both byte orders.
fn u32_words(algorithm: &'static str, table: impl Into<String>, words: &[u32], note: &'static str) -> Vec<Constant> {
    let little: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    word_orders(algorithm, table, little, size_of::<u32>(), note)
}

/// Patterns for a table of 64-bit words in both byte orders.
fn u64_words(algorithm: &'static str, table: impl Into<String>, words: &[u64], note: &'static str) -> Vec<Constant> {
    let little: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    word_orders(algorithm, table, little, size_of::<u64>(), note)
}

fn word_orders(algorithm: &'static str, table: impl Into<String>, little: Vec<u8>, word_size: usize, note: &'static str) -> Vec<Constant> {
    let table = table.into();
    let big = reversed_words(&little, word_size);
    let mut little_constant = Constant::plain(algorithm, table.clone(), little).with_note(note);
    little_constant.byte_order = "little-endian";
    let mut big_constant = Constant::plain(algorithm, table, big).with_note(note);
    big_constant.byte_order = "big-endian";
    vec![little_constant, big_constant]
}

/// Reverse the bytes within each `word_size` chunk.
fn reversed_words(bytes: &[u8], word_size: usize) -> Vec<u8> {
    bytes.chunks(word_size.max(1)).flat_map(|word| word.iter().rev().copied()).collect()
}

fn reversed(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

fn curve25519_prime_little_endian() -> Vec<u8> {
    // 2^255 - 19: 0xED, thirty 0xFF bytes, then 0x7F.
    let mut prime = vec![0xFF; 32];
    prime[0] = 0xED;
    prime[31] = 0x7F;
    prime
}

// ---------------------------------------------------------------------------
// Derived tables
// ---------------------------------------------------------------------------

/// Multiply in GF(2^8) with the AES reduction polynomial.
fn gf_multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= AES_REDUCTION;
        }
        b >>= 1;
    }
    product
}

/// Multiplicative inverse in GF(2^8); zero maps to zero. Uses a^254 = a^-1.
fn gf_inverse(value: u8) -> u8 {
    let mut result = 1u8;
    for _ in 0..254 {
        result = gf_multiply(result, value);
    }
    if value == 0 { 0 } else { result }
}

/// The AES substitution box: inverse in GF(2^8) followed by the affine transform.
pub fn aes_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    for (value, slot) in sbox.iter_mut().enumerate() {
        let inverse = gf_inverse(value as u8);
        *slot = inverse
            ^ inverse.rotate_left(1)
            ^ inverse.rotate_left(2)
            ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4)
            ^ AES_AFFINE_CONSTANT;
    }
    sbox
}

/// The inverse AES substitution box.
pub fn aes_inverse_sbox() -> [u8; 256] {
    let mut inverse = [0u8; 256];
    for (value, &substituted) in aes_sbox().iter().enumerate() {
        inverse[substituted as usize] = value as u8;
    }
    inverse
}

/// Te0: each S-box output times the MixColumns column (2, 1, 1, 3), packed
/// most significant byte first as in the reference implementation.
fn aes_encryption_table() -> Vec<u32> {
    aes_sbox().iter().map(|&s| u32::from_be_bytes([gf_multiply(s, 2), s, s, gf_multiply(s, 3)])).collect()
}

/// Td0: each inverse S-box output times the InvMixColumns column (14, 9, 13, 11).
fn aes_decryption_table() -> Vec<u32> {
    aes_inverse_sbox()
        .iter()
        .map(|&s| u32::from_be_bytes([gf_multiply(s, 14), gf_multiply(s, 9), gf_multiply(s, 13), gf_multiply(s, 11)]))
        .collect()
}

/// A 256-entry CRC-32 lookup table, for a normal (MSB-first) or reflected polynomial.
pub fn crc32_table(polynomial: u32, reflected: bool) -> Vec<u32> {
    (0..256u32)
        .map(|index| {
            let mut crc = if reflected { index } else { index << 24 };
            for _ in 0..8 {
                crc = if reflected {
                    if crc & 1 != 0 { (crc >> 1) ^ polynomial } else { crc >> 1 }
                } else if crc & 0x8000_0000 != 0 {
                    (crc << 1) ^ polynomial
                } else {
                    crc << 1
                };
            }
            crc
        })
        .collect()
}

/// A 256-entry CRC-16 lookup table, for a normal (MSB-first) or reflected polynomial.
pub fn crc16_table(polynomial: u16, reflected: bool) -> Vec<u16> {
    (0..256u16)
        .map(|index| {
            let mut crc = if reflected { index } else { index << 8 };
            for _ in 0..8 {
                crc = if reflected {
                    if crc & 1 != 0 { (crc >> 1) ^ polynomial } else { crc >> 1 }
                } else if crc & 0x8000 != 0 {
                    (crc << 1) ^ polynomial
                } else {
                    crc << 1
                };
            }
            crc
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Verification of short or partial patterns
// ---------------------------------------------------------------------------

/// Upgrade an RSA exponent hit when a DER INTEGER modulus ends right before it.
fn confirm_rsa_exponent(bytes: &[u8], at: usize, mut plain: CryptoMatch) -> CryptoMatch {
    let earliest = at.saturating_sub(MAX_RSA_MODULUS_BYTES + 4);
    for header in (earliest..at).rev() {
        let Some(modulus_len) = der_integer_ending_at(bytes, header, at) else { continue };
        let start_shift = at - header;
        let significant = if bytes.get(header + (start_shift - modulus_len)) == Some(&0) { modulus_len - 1 } else { modulus_len };
        plain.start -= start_shift;
        plain.len += start_shift;
        plain.table = "public key (exponent 65537)".to_string();
        plain.note = format!("DER modulus of {} bits followed by exponent 65537", significant * 8);
        plain.confidence = CONFIDENCE_LONG;
        return plain;
    }
    plain
}

/// If a long-form DER INTEGER header at `header` describes content that ends
/// exactly at `end`, return the content length.
fn der_integer_ending_at(bytes: &[u8], header: usize, end: usize) -> Option<usize> {
    if bytes.get(header) != Some(&DER_INTEGER) {
        return None;
    }
    let (header_len, content_len) = match *bytes.get(header + 1)? {
        DER_LENGTH_ONE_BYTE => (3, usize::from(*bytes.get(header + 2)?)),
        DER_LENGTH_TWO_BYTES => (4, usize::from(u16::from_be_bytes([*bytes.get(header + 2)?, *bytes.get(header + 3)?]))),
        _ => return None,
    };
    (content_len > 0 && header + header_len + content_len == end).then_some(content_len)
}

/// Accept the alphanumerics only when followed by a known pair of symbols.
fn confirm_base64_alphabet(bytes: &[u8], at: usize, mut plain: CryptoMatch) -> Option<CryptoMatch> {
    let tail = bytes.get(at + BASE64_CORE.len()..at + BASE64_CORE.len() + 2)?;
    plain.note = match tail {
        b"+/" => "standard alphabet (+/)".to_string(),
        b"-_" => "URL-safe alphabet (-_)".to_string(),
        b"./" => "crypt alphabet variant (./)".to_string(),
        _ => return None,
    };
    plain.len = BASE64_CORE.len() + 2;
    Some(plain)
}

/// Check the letters and symbols of a decoding table around a digit anchor.
fn confirm_base64_decode_table(bytes: &[u8], at: usize, base: usize, mut plain: CryptoMatch) -> Option<CryptoMatch> {
    let table_start = at.checked_sub(usize::from(b'0'))?;
    let table = bytes.get(table_start..table_start + BASE64_DECODE_TABLE_MIN_LEN)?;
    let letters_match = (0..26u8).all(|i| table[usize::from(b'A' + i)] == i && table[usize::from(b'a' + i)] == 26 + i);
    if !letters_match {
        return None;
    }
    let symbols = |plus: u8, slash: u8| table[usize::from(plus)] == 62 && table[usize::from(slash)] == 63;
    plain.note = if symbols(b'+', b'/') {
        "standard alphabet (+/)".to_string()
    } else if symbols(b'-', b'_') {
        "URL-safe alphabet (-_)".to_string()
    } else {
        return None;
    };
    plain.start = base + table_start;
    plain.len = BASE64_DECODE_TABLE_MIN_LEN;
    plain.confidence = CONFIDENCE_LONG;
    Some(plain)
}

/// Remove matches lying entirely inside another, keeping the first of equals.
fn drop_contained(mut matches: Vec<CryptoMatch>) -> Vec<CryptoMatch> {
    matches.sort_by(|a, b| a.start.cmp(&b.start).then(b.len.cmp(&a.len)));
    let mut kept: Vec<CryptoMatch> = Vec::with_capacity(matches.len());
    let mut furthest_end = 0usize;
    for candidate in matches {
        let end = candidate.start + candidate.len;
        if !kept.is_empty() && end <= furthest_end {
            continue;
        }
        furthest_end = furthest_end.max(end);
        kept.push(candidate);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic noise that contains no constants.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn embed(mut haystack: Vec<u8>, at: usize, needle: &[u8]) -> Vec<u8> {
        haystack[at..at + needle.len()].copy_from_slice(needle);
        haystack
    }

    fn titles(matches: &[CryptoMatch]) -> Vec<String> {
        matches.iter().map(|m| m.title()).collect()
    }

    #[test]
    fn the_generated_aes_tables_match_the_published_values() {
        let sbox = aes_sbox();
        assert_eq!(&sbox[..4], &[0x63, 0x7C, 0x77, 0x7B]);
        assert_eq!(sbox[0x53], 0xED);
        assert_eq!(aes_inverse_sbox()[..4], [0x52, 0x09, 0x6A, 0xD5]);
        assert_eq!(aes_encryption_table()[0], 0xC663_63A5);
        assert_eq!(aes_decryption_table()[0], 0x51F4_A750);
    }

    #[test]
    fn the_generated_crc_tables_match_the_published_values() {
        assert_eq!(crc32_table(CRC32_POLYNOMIAL_REFLECTED, true)[1], 0x7707_3096);
        assert_eq!(crc32_table(CRC32_POLYNOMIAL, false)[1], 0x04C1_1DB7);
        assert_eq!(crc32_table(CRC32C_POLYNOMIAL_REFLECTED, true)[1], 0xF26B_8303);
        assert_eq!(crc16_table(CRC16_CCITT_POLYNOMIAL, false)[1], 0x1021);
        assert_eq!(crc16_table(CRC16_ARC_POLYNOMIAL_REFLECTED, true)[1], 0xC0C1);
        assert_eq!(crc16_table(CRC16_CCITT_POLYNOMIAL_REFLECTED, true)[1], 0x1189);
    }

    #[test]
    fn literal_hash_constants_agree_with_their_mathematical_definitions() {
        let primes = [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];
        let fraction_bits = |value: f64| ((value - value.floor()) * 4_294_967_296.0) as u32;
        for (index, &prime) in primes.iter().enumerate() {
            assert_eq!(SHA256_ROUND_PREFIX[index], fraction_bits(f64::from(prime).cbrt()), "K[{index}]");
        }
        for (index, &prime) in primes.iter().take(8).enumerate() {
            assert_eq!(SHA256_INITIAL[index], fraction_bits(f64::from(prime).sqrt()), "H[{index}]");
            assert_eq!((SHA512_INITIAL[index] >> 32) as u32, SHA256_INITIAL[index]);
            assert_eq!(SHA384_INITIAL_PREFIX.get(index).map(|&word| word as u32), (index < 4).then(|| SHA224_INITIAL[index]));
        }
        for (index, &constant) in MD5_SINE_PREFIX.iter().enumerate() {
            let expected = ((index as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32;
            assert_eq!(constant, expected, "T[{index}]");
        }
    }

    #[test]
    fn every_des_sbox_row_is_a_permutation_of_sixteen_values() {
        for row in DES_SBOX1.chunks(16) {
            let mut sorted = row.to_vec();
            sorted.sort_unstable();
            assert_eq!(sorted, (0..16).collect::<Vec<u8>>());
        }
    }

    #[test]
    fn an_aes_sbox_in_firmware_is_found_at_its_offset() {
        let data = embed(noise(8192, 1), 1000, &aes_sbox());
        let found = scan_constants(&data, 0x4000);
        let sbox = found.iter().find(|m| m.title() == "AES S-box").expect("the S-box");
        assert_eq!(sbox.start, 0x4000 + 1000);
        assert_eq!(sbox.len, 256);
        assert!(sbox.confidence >= 0.9);
    }

    #[test]
    fn a_big_endian_sha256_initial_value_block_is_found_with_its_byte_order() {
        let words: Vec<u8> = SHA256_INITIAL.iter().flat_map(|w| w.to_be_bytes()).collect();
        let found = scan_constants(&embed(noise(512, 2), 64, &words), 0);
        assert_eq!(titles(&found), vec!["SHA-256 initial values"]);
        assert_eq!(found[0].byte_order, "big-endian");
        assert_eq!(found[0].start, 64);
    }

    #[test]
    fn a_sha1_initial_value_block_is_not_also_reported_as_md5() {
        let words: Vec<u8> = SHA1_INITIAL.iter().flat_map(|w| w.to_le_bytes()).collect();
        let found = scan_constants(&embed(noise(512, 3), 100, &words), 0);
        assert_eq!(titles(&found), vec!["SHA-1 initial values"]);
    }

    #[test]
    fn a_reflected_crc32_table_is_recognised() {
        let table: Vec<u8> = crc32_table(CRC32_POLYNOMIAL_REFLECTED, true).iter().flat_map(|w| w.to_le_bytes()).collect();
        let found = scan_constants(&embed(noise(4096, 4), 16, &table), 0);
        assert!(found.iter().any(|m| m.algorithm == "CRC-32" && m.table.contains("reflected") && m.start == 16), "{:?}", titles(&found));
    }

    #[test]
    fn chacha_sigma_and_a_deflate_length_table_are_both_found() {
        let lengths: Vec<u8> = DEFLATE_LENGTH_BASE.iter().flat_map(|v| v.to_le_bytes()).collect();
        let data = embed(embed(noise(2048, 5), 10, b"expand 32-byte k"), 500, &lengths);
        let found = titles(&scan_constants(&data, 0));
        assert!(found.contains(&"ChaCha/Salsa20 sigma constant".to_string()), "{found:?}");
        assert!(found.contains(&"Deflate length base table".to_string()), "{found:?}");
    }

    #[test]
    fn an_rsa_exponent_after_a_der_modulus_is_reported_as_a_public_key() {
        let mut key = vec![0x02, 0x82, 0x01, 0x01, 0x00];
        key.extend(noise(256, 6));
        key.extend_from_slice(&DER_EXPONENT_65537);
        let found = scan_constants(&embed(noise(2048, 7), 300, &key), 0);
        let rsa = found.iter().find(|m| m.algorithm == "RSA").expect("an RSA match");
        assert_eq!(rsa.start, 300);
        assert_eq!(rsa.len, key.len());
        assert!(rsa.note.contains("2048 bits"), "{}", rsa.note);
        assert!(rsa.confidence >= 0.9);
    }

    #[test]
    fn a_lone_rsa_exponent_is_reported_with_low_confidence() {
        let found = scan_constants(&embed(noise(256, 8), 40, &DER_EXPONENT_65537), 0);
        let rsa = found.iter().find(|m| m.algorithm == "RSA").expect("an RSA match");
        assert!(rsa.confidence < 0.5);
    }

    #[test]
    fn base64_alphabets_and_decoding_tables_name_their_variant() {
        let mut alphabet = BASE64_CORE.to_vec();
        alphabet.extend_from_slice(b"-_");
        let mut decode = vec![0xFFu8; 256];
        for (value, &symbol) in BASE64_CORE.iter().chain(b"+/").enumerate() {
            decode[usize::from(symbol)] = value as u8;
        }
        let data = embed(embed(noise(2048, 9), 100, &alphabet), 1024, &decode);
        let found = scan_constants(&data, 0);
        let alphabet_match = found.iter().find(|m| m.table == "alphabet").expect("the alphabet");
        assert!(alphabet_match.note.contains("URL-safe"));
        assert_eq!(alphabet_match.len, 64);
        let table = found.iter().find(|m| m.table == "decoding table").expect("the decoding table");
        assert_eq!(table.start, 1024);
        assert!(table.note.contains("standard"));
    }

    #[test]
    fn random_empty_and_tiny_inputs_produce_no_matches() {
        assert!(scan_constants(&[], 0).is_empty());
        assert!(scan_constants(&[0x02, 0x03, 0x01], 0).is_empty());
        assert!(scan_constants(&noise(1 << 20, 10), 0).iter().all(|m| m.confidence < 0.5));
    }

    #[test]
    fn the_detector_reports_encoding_findings_at_document_offsets() {
        let data = embed(noise(1024, 11), 200, &aes_inverse_sbox());
        let context = ScanContext { base: 0x1_0000, document_len: 0x2_0000, strides: Vec::new() };
        let findings = CryptoConstantDetector.scan(&data, &context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::Encoding);
        assert_eq!(findings[0].start, 0x1_0000 + 200);
        assert_eq!(findings[0].title, "AES inverse S-box");
        assert_eq!(findings[0].id, "crypto:aes");
        assert_eq!(findings[0].source, DETECTOR_ID);
    }
}
