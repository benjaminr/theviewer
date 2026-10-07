//! Block-cipher decryption: AES-128, AES-192 and AES-256 in ECB, CBC or CTR
//! mode, with PKCS#7 padding or none.
//!
//! The crypto searches lead to a key and a confirmed cipher (an AES S-box,
//! a raw key amid structured data, ECB's repeated blocks); this undoes the
//! encryption. The modes are written out here over the `aes` crate's single
//! block function, so a wrong key or a damaged block still gives bytes to
//! look at rather than an error: only a key of the wrong length, a missing
//! IV or ciphertext that is not whole blocks is refused. Everything here is
//! pure: no document, no UI.

use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};

/// Bytes in an AES block, and in its IV or initial counter.
pub const BLOCK_BYTES: usize = 16;

/// Which AES, named by its key size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub enum Algorithm {
    #[serde(rename = "aes-128")]
    Aes128,
    #[serde(rename = "aes-192")]
    Aes192,
    #[serde(rename = "aes-256")]
    Aes256,
}

impl Algorithm {
    pub const ALL: [Algorithm; 3] = [Algorithm::Aes128, Algorithm::Aes192, Algorithm::Aes256];

    /// Bytes of key it takes.
    pub fn key_bytes(self) -> usize {
        match self {
            Algorithm::Aes128 => 16,
            Algorithm::Aes192 => 24,
            Algorithm::Aes256 => 32,
        }
    }

    /// The AES a key of `len` bytes is for, if any.
    pub fn for_key_len(len: usize) -> Option<Algorithm> {
        Algorithm::ALL.into_iter().find(|algorithm| algorithm.key_bytes() == len)
    }

    pub fn label(self) -> &'static str {
        match self {
            Algorithm::Aes128 => "AES-128",
            Algorithm::Aes192 => "AES-192",
            Algorithm::Aes256 => "AES-256",
        }
    }
}

/// How the blocks are chained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Each block decrypted on its own.
    Ecb,
    /// Each decrypted block XORed with the ciphertext block before it, the
    /// first with the IV.
    Cbc,
    /// The data XORed with encrypted counter blocks: the IV taken as a
    /// 128-bit big-endian counter, one more for each block. Any length.
    Ctr,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Ecb, Mode::Cbc, Mode::Ctr];

    pub fn label(self) -> &'static str {
        match self {
            Mode::Ecb => "ECB",
            Mode::Cbc => "CBC",
            Mode::Ctr => "CTR",
        }
    }

    /// Whether it takes an IV (or, for CTR, the initial counter block).
    pub fn needs_iv(self) -> bool {
        !matches!(self, Mode::Ecb)
    }

    /// The padding usual with it: PKCS#7 for the block modes, none for CTR,
    /// which needs no whole blocks.
    pub fn usual_padding(self) -> Padding {
        match self {
            Mode::Ecb | Mode::Cbc => Padding::Pkcs7,
            Mode::Ctr => Padding::None,
        }
    }
}

/// What fills out the last block before encryption, removed after.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Padding {
    /// 1 to 16 bytes, each holding the count.
    Pkcs7,
    /// Nothing is removed.
    None,
}

impl Padding {
    pub fn label(self) -> &'static str {
        match self {
            Padding::Pkcs7 => "PKCS#7",
            Padding::None => "no padding",
        }
    }
}

/// A decryption to carry out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decryption {
    pub algorithm: Algorithm,
    pub mode: Mode,
    pub key: Vec<u8>,
    /// The IV for CBC, the initial counter block for CTR; unused by ECB.
    pub iv: Option<Vec<u8>>,
    pub padding: Padding,
}

/// What a decryption gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decrypted {
    /// The plaintext, padding removed when it was valid.
    pub bytes: Vec<u8>,
    /// Padding bytes removed.
    pub padding_removed: usize,
    /// Whether PKCS#7 padding was asked for and the last block did not end
    /// with it, which usually means a wrong key, IV or mode; the bytes are
    /// then left whole.
    pub padding_invalid: bool,
}

/// One AES, whichever its key size.
enum Cipher {
    Aes128(Box<Aes128>),
    Aes192(Box<Aes192>),
    Aes256(Box<Aes256>),
}

impl Cipher {
    fn new(algorithm: Algorithm, key: &[u8]) -> Result<Cipher, String> {
        if key.len() != algorithm.key_bytes() {
            return Err(format!("{} takes a {}-byte key, but the key given is {} bytes", algorithm.label(), algorithm.key_bytes(), key.len()));
        }
        let wrong_length = |_| format!("{} cannot use a {}-byte key", algorithm.label(), key.len());
        Ok(match algorithm {
            Algorithm::Aes128 => Cipher::Aes128(Box::new(Aes128::new_from_slice(key).map_err(wrong_length)?)),
            Algorithm::Aes192 => Cipher::Aes192(Box::new(Aes192::new_from_slice(key).map_err(wrong_length)?)),
            Algorithm::Aes256 => Cipher::Aes256(Box::new(Aes256::new_from_slice(key).map_err(wrong_length)?)),
        })
    }

    fn decrypt_block(&self, block: &mut [u8; BLOCK_BYTES]) {
        let mut array = Array::from(*block);
        match self {
            Cipher::Aes128(cipher) => cipher.decrypt_block(&mut array),
            Cipher::Aes192(cipher) => cipher.decrypt_block(&mut array),
            Cipher::Aes256(cipher) => cipher.decrypt_block(&mut array),
        }
        *block = array.into();
    }

    fn encrypt_block(&self, block: &mut [u8; BLOCK_BYTES]) {
        let mut array = Array::from(*block);
        match self {
            Cipher::Aes128(cipher) => cipher.encrypt_block(&mut array),
            Cipher::Aes192(cipher) => cipher.encrypt_block(&mut array),
            Cipher::Aes256(cipher) => cipher.encrypt_block(&mut array),
        }
        *block = array.into();
    }
}

/// Decrypt `ciphertext` as `decryption` says. Refused only when the key
/// does not fit the algorithm, the mode's IV is missing or not 16 bytes, or
/// ECB or CBC ciphertext is not whole blocks.
pub fn decrypt(decryption: &Decryption, ciphertext: &[u8]) -> Result<Decrypted, String> {
    let cipher = Cipher::new(decryption.algorithm, &decryption.key)?;
    let iv = initial_block(decryption)?;
    let mode = decryption.mode;
    if mode != Mode::Ctr && !ciphertext.len().is_multiple_of(BLOCK_BYTES) {
        return Err(format!(
            "{} decrypts whole 16-byte blocks, but {} bytes is {} blocks and {} bytes over; check the start and length",
            mode.label(),
            ciphertext.len(),
            ciphertext.len() / BLOCK_BYTES,
            ciphertext.len() % BLOCK_BYTES
        ));
    }
    let mut plaintext = match mode {
        Mode::Ecb => decrypt_ecb(&cipher, ciphertext),
        Mode::Cbc => decrypt_cbc(&cipher, ciphertext, iv),
        Mode::Ctr => apply_ctr(&cipher, ciphertext, iv),
    };
    let (padding_removed, padding_invalid) = match decryption.padding {
        Padding::None => (0, false),
        Padding::Pkcs7 => match pkcs7_padding_len(&plaintext) {
            Some(len) => (len, false),
            None => (0, true),
        },
    };
    plaintext.truncate(plaintext.len() - padding_removed);
    Ok(Decrypted { bytes: plaintext, padding_removed, padding_invalid })
}

/// The IV or initial counter block, all zeros for ECB, which uses none.
fn initial_block(decryption: &Decryption) -> Result<[u8; BLOCK_BYTES], String> {
    if !decryption.mode.needs_iv() {
        return Ok([0; BLOCK_BYTES]);
    }
    let what = if decryption.mode == Mode::Ctr { "an initial counter block as iv" } else { "an iv" };
    let iv = decryption.iv.as_deref().ok_or_else(|| format!("{} needs {what} of 16 bytes, such as 00000000000000000000000000000000", decryption.mode.label()))?;
    iv.try_into().map_err(|_| format!("{} needs {what} of 16 bytes, but {} were given", decryption.mode.label(), iv.len()))
}

fn decrypt_ecb(cipher: &Cipher, ciphertext: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for &block in ciphertext.as_chunks::<BLOCK_BYTES>().0 {
        let mut block = block;
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }
    plaintext
}

fn decrypt_cbc(cipher: &Cipher, ciphertext: &[u8], iv: [u8; BLOCK_BYTES]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut previous = iv;
    for &encrypted in ciphertext.as_chunks::<BLOCK_BYTES>().0 {
        let mut block = encrypted;
        cipher.decrypt_block(&mut block);
        plaintext.extend(block.iter().zip(previous).map(|(byte, chained)| byte ^ chained));
        previous = encrypted;
    }
    plaintext
}

/// CTR encrypts and decrypts alike: XOR with the encrypted counter blocks.
fn apply_ctr(cipher: &Cipher, data: &[u8], initial_counter: [u8; BLOCK_BYTES]) -> Vec<u8> {
    let mut counter = u128::from_be_bytes(initial_counter);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK_BYTES) {
        let mut keystream = counter.to_be_bytes();
        cipher.encrypt_block(&mut keystream);
        out.extend(chunk.iter().zip(keystream).map(|(byte, key)| byte ^ key));
        counter = counter.wrapping_add(1);
    }
    out
}

/// The length of valid PKCS#7 padding at the end of `plaintext`, if any.
fn pkcs7_padding_len(plaintext: &[u8]) -> Option<usize> {
    let &last = plaintext.last()?;
    let len = last as usize;
    let valid = (1..=BLOCK_BYTES).contains(&len) && len <= plaintext.len() && plaintext[plaintext.len() - len..].iter().all(|&byte| byte == last);
    valid.then_some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        crate::ops::parse_hex(text).unwrap()
    }

    fn decryption(algorithm: Algorithm, mode: Mode, key: &str, iv: Option<&str>, padding: Padding) -> Decryption {
        Decryption { algorithm, mode, key: hex(key), iv: iv.map(hex), padding }
    }

    // Vectors from NIST SP 800-38A, appendix F: the first two blocks of each.
    const NIST_PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
    const NIST_KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const NIST_KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    const NIST_KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

    #[test]
    fn ecb_ciphertext_from_the_standard_decrypts_with_each_key_size() {
        let cases = [
            (Algorithm::Aes128, NIST_KEY_128, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"),
            (Algorithm::Aes192, NIST_KEY_192, "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef"),
            (Algorithm::Aes256, NIST_KEY_256, "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"),
        ];
        for (algorithm, key, ciphertext) in cases {
            let decrypted = decrypt(&decryption(algorithm, Mode::Ecb, key, None, Padding::None), &hex(ciphertext)).unwrap();
            assert_eq!(decrypted.bytes, hex(NIST_PLAINTEXT), "{}", algorithm.label());
        }
    }

    #[test]
    fn cbc_and_ctr_ciphertext_from_the_standard_decrypts_with_its_iv() {
        let cbc = decryption(Algorithm::Aes128, Mode::Cbc, NIST_KEY_128, Some("000102030405060708090a0b0c0d0e0f"), Padding::None);
        let decrypted = decrypt(&cbc, &hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")).unwrap();
        assert_eq!(decrypted.bytes, hex(NIST_PLAINTEXT));
        let ctr = decryption(Algorithm::Aes128, Mode::Ctr, NIST_KEY_128, Some("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), Padding::None);
        let decrypted = decrypt(&ctr, &hex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff")).unwrap();
        assert_eq!(decrypted.bytes, hex(NIST_PLAINTEXT));
        let partial = decrypt(&ctr, &hex("874d6191b620e3261bef6864990db6ce9806")).unwrap();
        assert_eq!(partial.bytes, hex(NIST_PLAINTEXT)[..18], "CTR takes any length");
    }

    #[test]
    fn valid_pkcs7_padding_is_removed_and_invalid_padding_is_left_and_flagged() {
        let key = Algorithm::Aes128;
        let cipher = Cipher::new(key, &hex(NIST_KEY_128)).unwrap();
        let mut padded = *b"FLAG{ecb}\x07\x07\x07\x07\x07\x07\x07";
        cipher.encrypt_block(&mut padded);
        let ecb = decryption(key, Mode::Ecb, NIST_KEY_128, None, Padding::Pkcs7);
        let decrypted = decrypt(&ecb, &padded).unwrap();
        assert_eq!((decrypted.bytes.as_slice(), decrypted.padding_removed, decrypted.padding_invalid), (b"FLAG{ecb}".as_slice(), 7, false));

        let wrong_key = decryption(key, Mode::Ecb, "000102030405060708090a0b0c0d0e0f", None, Padding::Pkcs7);
        let garbled = decrypt(&wrong_key, &padded).unwrap();
        assert!(garbled.padding_invalid, "a wrong key rarely leaves valid padding");
        assert_eq!(garbled.bytes.len(), BLOCK_BYTES, "the bytes are kept whole to look at");
    }

    #[test]
    fn a_key_of_the_wrong_size_a_missing_iv_or_part_blocks_are_refused_with_the_reason() {
        let short_key = decrypt(&decryption(Algorithm::Aes256, Mode::Ecb, NIST_KEY_128, None, Padding::None), &[0; 16]).unwrap_err();
        assert!(short_key.contains("32-byte key") && short_key.contains("16 bytes"), "{short_key}");
        let no_iv = decrypt(&decryption(Algorithm::Aes128, Mode::Cbc, NIST_KEY_128, None, Padding::None), &[0; 16]).unwrap_err();
        assert!(no_iv.contains("iv"), "{no_iv}");
        let short_iv = decrypt(&decryption(Algorithm::Aes128, Mode::Ctr, NIST_KEY_128, Some("0001"), Padding::None), &[0; 16]).unwrap_err();
        assert!(short_iv.contains("2 were given"), "{short_iv}");
        let ragged = decrypt(&decryption(Algorithm::Aes128, Mode::Ecb, NIST_KEY_128, None, Padding::None), &[0; 20]).unwrap_err();
        assert!(ragged.contains("4 bytes over"), "{ragged}");
        assert!(decrypt(&decryption(Algorithm::Aes128, Mode::Ecb, NIST_KEY_128, None, Padding::Pkcs7), &[]).unwrap().padding_invalid, "nothing has no padding");
    }

    #[test]
    fn the_algorithm_follows_from_the_key_length() {
        assert_eq!(Algorithm::for_key_len(24), Some(Algorithm::Aes192));
        assert_eq!(Algorithm::for_key_len(20), None);
        assert_eq!(serde_json::to_value(Algorithm::Aes256).unwrap(), "aes-256");
        assert_eq!(serde_json::from_value::<Mode>("ctr".into()).unwrap(), Mode::Ctr);
    }
}
