//! XOR key recovery for obfuscated data.
//!
//! Plain XOR with a short repeating key is the most common "encryption" in
//! firmware and malware. Two kinds of evidence recover it:
//!
//! * text: decoded bytes look like English or other printable text;
//! * zeros: binary formats are full of zero bytes, and zero XOR key = key, so
//!   the right key turns the most common ciphertext bytes back into zeros and
//!   long zero runs show the key repeating verbatim.
//!
//! Keys are always phase-aligned: `key[i % len]` decodes `bytes[i]`.

use std::collections::HashMap;

/// A proposed key with how well it decodes the data.
#[derive(Clone, Debug, PartialEq)]
pub struct XorCandidate {
    pub key: Vec<u8>,
    /// Higher is better: the larger of how text-like and how zero-rich the
    /// decoded data is (0 to 1), except that a key nearly repeating a
    /// shorter one that scores about as well takes the shorter one's score
    /// (see `ranking_score`). Candidates come in the order of their scores.
    pub score: f64,
    pub printable_fraction: f64,
    /// First 64 decoded bytes, unprintable ones as '.'.
    pub preview: String,
    pub reason: String,
}

/// Most bytes examined.
const SAMPLE: usize = 1024 * 1024;
/// Key lengths solved column by column.
const LENGTHS_TO_SOLVE: usize = 3;
/// A key is offered folded to a shorter period when at least this share of
/// its bytes equal the shorter key's: with few bytes per column, a long key
/// solves one or two columns of the true short key wrongly.
const FOLD_AGREEMENT: f64 = 0.9;
/// Scores closer than this count as a tie, which the shorter of a key and
/// its fold wins: the long key's extra freedom fits noise, not the data.
const FOLD_SCORE_TIE: f64 = 0.01;

/// XOR `bytes` with `key`, where `bytes[0]` lines up with `key[key_phase]`.
/// Applying it twice gives the original back.
pub fn apply(bytes: &[u8], key: &[u8], key_phase: usize) -> Vec<u8> {
    if key.is_empty() {
        return bytes.to_vec();
    }
    bytes.iter().enumerate().map(|(i, &b)| b ^ key[(i + key_phase) % key.len()]).collect()
}

/// Rank key lengths 1..=max_len by the index of coincidence of their columns
/// (the chance two bytes in a column are equal). Bytes XORed with the same key
/// byte keep the plaintext's uneven distribution, so the true length and its
/// multiples score high; ties go to the shorter length. Lengths whose columns
/// would hold fewer than two bytes are skipped.
pub fn guess_key_lengths(bytes: &[u8], max_len: usize) -> Vec<(usize, f64)> {
    let bytes = &bytes[..bytes.len().min(SAMPLE)];
    let mut ranked: Vec<(usize, f64)> = (1..=max_len.max(1))
        .filter(|&len| bytes.len() / len >= 2)
        .map(|len| {
            let total: f64 = (0..len).map(|column| coincidence(bytes.iter().skip(column).step_by(len).copied())).sum();
            (len, total / len as f64)
        })
        .collect();
    // Multiples of the true length score about as well as the length itself,
    // sometimes a little better by chance; among lengths within 10% of the
    // best score, the shortest comes first.
    let best = ranked.iter().map(|&(_, ic)| ic).fold(0.0, f64::max);
    let rank = |&(len, ic): &(usize, f64)| if ic >= best * 0.9 { 2.0 + 1.0 / len as f64 } else { ic };
    ranked.sort_by(|a, b| rank(b).total_cmp(&rank(a)));
    ranked
}

fn coincidence(column: impl Iterator<Item = u8>) -> f64 {
    let mut counts = [0u64; 256];
    let mut n = 0u64;
    for byte in column {
        counts[byte as usize] += 1;
        n += 1;
    }
    if n < 2 {
        return 0.0;
    }
    let pairs: u64 = counts.iter().map(|&c| c * c.saturating_sub(1)).sum();
    pairs as f64 / (n * (n - 1)) as f64
}

/// How much one decoded byte looks like English text (0 to 1).
fn text_weight(byte: u8) -> f64 {
    // Relative English letter frequencies, most common first.
    const ORDER: &[u8] = b"etaoinshrdlcumwfgypbvkjxqz";
    match byte {
        b' ' => 1.0,
        b'a'..=b'z' => {
            let rank = ORDER.iter().position(|&c| c == byte).unwrap_or(25);
            0.95 - rank as f64 * 0.02
        }
        b'A'..=b'Z' => 0.45,
        b'0'..=b'9' => 0.3,
        b'\n' | b'\r' | b'\t' => 0.3,
        0x21..=0x7E => 0.2,
        _ => 0.0,
    }
}

/// Largest share any one character may contribute to the text score. Zero
/// padding XORed with the wrong key decodes to pages of one character (spaces,
/// or "e"), which is not text; in English even the space is under 20%.
const MAX_CHARACTER_SHARE: f64 = 0.2;

/// Text-likeness of byte counts, each character capped at an English-like share.
fn text_score(counts: &[u64; 256], n: f64) -> f64 {
    let cap = n * MAX_CHARACTER_SHARE;
    let total: f64 = counts.iter().enumerate().map(|(value, &count)| text_weight(value as u8) * (count as f64).min(cap)).sum();
    total / n
}

/// Text-likeness and zero fraction of decoded data.
fn evaluate(decoded: &[u8]) -> (f64, f64, f64) {
    if decoded.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let n = decoded.len() as f64;
    let mut counts = [0u64; 256];
    for &b in decoded {
        counts[b as usize] += 1;
    }
    let text = text_score(&counts, n);
    let zeros = decoded.iter().filter(|&&b| b == 0).count() as f64 / n;
    let printable = decoded.iter().filter(|&&b| (0x20..0x7F).contains(&b) || matches!(b, 9 | 10 | 13)).count() as f64 / n;
    (text, zeros, printable)
}

/// Best key byte for one column: the byte that makes it most text-like or
/// most zero-rich.
fn solve_column(column: &[u8]) -> u8 {
    let mut counts = [0u32; 256];
    for &b in column {
        counts[b as usize] += 1;
    }
    let n = column.len().max(1) as f64;
    (0..=255u8)
        .max_by(|&a, &b| column_score(&counts, a, n).total_cmp(&column_score(&counts, b, n)))
        .unwrap_or(0)
}

fn column_score(counts: &[u32; 256], key: u8, n: f64) -> f64 {
    let mut decoded = [0u64; 256];
    for (value, &count) in counts.iter().enumerate() {
        decoded[value ^ key as usize] = count as u64;
    }
    let zeros = counts[key as usize] as f64;
    text_score(&decoded, n).max(zeros / n)
}

/// Propose XOR keys, best first, at most `top`.
pub fn recover_keys(bytes: &[u8], max_key_len: usize, top: usize) -> Vec<XorCandidate> {
    let bytes = &bytes[..bytes.len().min(SAMPLE)];
    if bytes.is_empty() || top == 0 {
        return Vec::new();
    }
    let max_key_len = max_key_len.clamp(1, 256);
    let mut candidates: Vec<(Vec<u8>, String)> = Vec::new();

    // Single-byte keys, scored by text.
    let mut single: Vec<(u8, f64)> = (0..=255u8).map(|k| (k, evaluate(&apply(&bytes[..bytes.len().min(65_536)], &[k], 0)).0)).collect();
    single.sort_by(|a, b| b.1.total_cmp(&a.1));
    for &(key, _) in single.iter().take(3) {
        candidates.push((vec![key], "single byte; decodes to text".to_string()));
    }
    // Single-byte key from the most common byte becoming zero.
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let most_common = (0..=255u8).max_by_key(|&b| counts[b as usize]).unwrap_or(0);
    candidates.push((vec![most_common], format!("single byte; the most common byte ({most_common:#04x}) becomes 0x00")));

    // Multi-byte keys, column by column, for the most likely lengths.
    let lengths = guess_key_lengths(bytes, max_key_len);
    let key_period = lengths.iter().map(|&(len, _)| len).find(|&len| len >= 2);
    for (len, _) in lengths.into_iter().filter(|&(len, _)| len >= 2).take(LENGTHS_TO_SOLVE) {
        let key: Vec<u8> = (0..len)
            .map(|column| solve_column(&bytes.iter().skip(column).step_by(len).copied().collect::<Vec<u8>>()))
            .collect();
        candidates.push((key, format!("{len}-byte key solved column by column")));
    }

    // A key repeating verbatim where the plaintext was zeros.
    if let Some((key, start)) = key_from_zero_run(bytes, max_key_len) {
        candidates.push((key, format!("repeating key seen verbatim in a run at {start:#x} that was probably zeros")));
    }

    // Each long key also folded to the shortest period it nearly repeats.
    let folds: Vec<(Vec<u8>, String)> = candidates
        .iter()
        .filter_map(|(key, _)| {
            let key = minimal_period(key);
            let (folded, agreeing) = fold_to_shorter_period(bytes, &key)?;
            let reason = format!("{}-byte key folded from a {}-byte one, {agreeing} of whose {} bytes repeat it", folded.len(), key.len(), key.len());
            Some((folded, reason))
        })
        .collect();
    candidates.extend(folds);

    let mut seen: HashMap<Vec<u8>, ()> = HashMap::new();
    let ranked: Vec<XorCandidate> = candidates
        .into_iter()
        .filter_map(|(key, reason)| {
            let key = minimal_period(&key);
            if seen.insert(key.clone(), ()).is_some() {
                return None;
            }
            let decoded = apply(bytes, &key, 0);
            let (text, zeros, printable) = evaluate(&decoded);
            let echo = key_period.map_or(0.0, |period| key_echo(&decoded, period));
            let preview: String = decoded.iter().take(64).map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' }).collect();
            Some(XorCandidate { key, score: (text * (1.0 - echo)).max(zeros), printable_fraction: printable, preview, reason })
        })
        .collect();
    let ranking: Vec<f64> = ranked.iter().map(|candidate| ranking_score(candidate, &ranked)).collect();
    let mut ranked: Vec<XorCandidate> = ranking.into_iter().zip(ranked).map(|(score, candidate)| XorCandidate { score, ..candidate }).collect();
    ranked.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.key.len().cmp(&b.key.len())));
    ranked.truncate(top);
    ranked
}

/// The score `candidate` is ranked by: its own, except that a key which
/// nearly repeats a shorter candidate scoring within [`FOLD_SCORE_TIE`] of
/// it takes that shorter key's score, so ranks after it (ties go to the
/// shorter key).
fn ranking_score(candidate: &XorCandidate, all: &[XorCandidate]) -> f64 {
    all.iter()
        .filter(|shorter| shorter.key.len() < candidate.key.len() && candidate.score - shorter.score <= FOLD_SCORE_TIE)
        .filter(|shorter| repeats_nearly(&candidate.key, &shorter.key))
        .map(|shorter| shorter.score)
        .fold(candidate.score, f64::min)
}

/// Whether `key` is `shorter` repeated, at least [`FOLD_AGREEMENT`] of its
/// bytes agreeing.
fn repeats_nearly(key: &[u8], shorter: &[u8]) -> bool {
    !shorter.is_empty() && key.len().is_multiple_of(shorter.len()) && agreement(key, shorter) as f64 >= FOLD_AGREEMENT * key.len() as f64
}

/// How many bytes of `key` equal `shorter` repeated.
fn agreement(key: &[u8], shorter: &[u8]) -> usize {
    key.iter().enumerate().filter(|&(i, &byte)| byte == shorter[i % shorter.len()]).count()
}

/// The shortest period that `key` nearly repeats: the key solved column by
/// column from `bytes` at each period dividing the key's length, shortest
/// first, until one agrees with at least [`FOLD_AGREEMENT`] of the key's
/// bytes. Returns the folded key and how many bytes agreed; `None` when the
/// key repeats no shorter period, or does so exactly.
fn fold_to_shorter_period(bytes: &[u8], key: &[u8]) -> Option<(Vec<u8>, usize)> {
    (1..key.len()).filter(|&period| key.len().is_multiple_of(period)).find_map(|period| {
        let folded: Vec<u8> = (0..period).map(|column| solve_column(&bytes.iter().skip(column).step_by(period).copied().collect::<Vec<u8>>())).collect();
        let agreeing = agreement(key, &folded);
        (repeats_nearly(key, &folded) && agreeing < key.len()).then_some((folded, agreeing))
    })
}

/// Share of `decoded` that repeats `period` bytes later without being a run
/// of one value: a repeating key showing through zeros. Zeros XORed with
/// "MODBUS" under a key that only flips case read "modbusmodbus", letters
/// but not text, so that much of a candidate's text score does not count.
fn key_echo(decoded: &[u8], period: usize) -> f64 {
    if decoded.len() <= period {
        return 0.0;
    }
    let echoes = decoded.windows(period + 1).filter(|window| window[0] == window[period] && window[0] != window[1]).count();
    echoes as f64 / (decoded.len() - period) as f64
}

/// Shortest repeating unit of `key` ("ABAB" becomes "AB").
fn minimal_period(key: &[u8]) -> Vec<u8> {
    for period in 1..key.len() {
        if key.len().is_multiple_of(period) && key.iter().enumerate().all(|(i, &b)| b == key[i % period]) {
            return key[..period].to_vec();
        }
    }
    key.to_vec()
}

/// Find the shortest period `p` (2..=max_len) with a long stretch where every
/// byte equals the one `p` later, and not just one repeated value. If the
/// plaintext there was zeros, the stretch is the key itself; return it
/// phase-aligned to offset 0, with where the stretch starts.
fn key_from_zero_run(bytes: &[u8], max_len: usize) -> Option<(Vec<u8>, usize)> {
    for period in 2..=max_len.min(bytes.len() / 4) {
        let needed = (period * 6).max(48);
        let mut run = 0usize;
        for i in 0..bytes.len() - period {
            if bytes[i] == bytes[i + period] {
                run += 1;
                if run >= needed {
                    let start = i + 1 - run;
                    let window = &bytes[start..start + period];
                    if window.iter().all(|&b| b == window[0]) {
                        break;
                    }
                    let key: Vec<u8> = (0..period).map(|phase| bytes[start + (phase + period - start % period) % period]).collect();
                    return Some((key, start));
                }
            } else {
                run = 0;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "It is a truth universally acknowledged, that a single man in possession of a good fortune, \
must be in want of a wife. However little known the feelings or views of such a man may be on his first entering a \
neighbourhood, this truth is so well fixed in the minds of the surrounding families, that he is considered the rightful \
property of some one or other of their daughters. My dear Mr. Bennet, said his lady to him one day, have you heard that \
Netherfield Park is let at last? Mr. Bennet replied that he had not. But it is, returned she; for Mrs. Long has just been \
here, and she told me all about it. Mr. Bennet made no answer. Do you not want to know who has taken it? cried his wife \
impatiently. You want to tell me, and I have no objection to hearing it. This was invitation enough.";

    fn noise(len: usize, mut state: u32) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    /// A binary-looking buffer: structured header, noise and zero padding.
    fn binary_with_padding() -> Vec<u8> {
        let mut bytes = b"\x7fELF\x02\x01\x01\x00".to_vec();
        bytes.extend(noise(600, 42));
        bytes.extend(std::iter::repeat_n(0u8, 2000));
        bytes.extend(noise(400, 7));
        bytes.extend(std::iter::repeat_n(0u8, 1000));
        bytes
    }

    #[test]
    fn single_byte_key_on_text_is_found_first() {
        let cipher = apply(TEXT.as_bytes(), &[0x5A], 0);
        let found = recover_keys(&cipher, 16, 5);
        assert_eq!(found[0].key, vec![0x5A], "{found:?}");
        assert!(found[0].preview.starts_with("It is a truth"));
        assert!(found[0].printable_fraction > 0.99);
    }

    #[test]
    fn zero_padding_reveals_a_single_byte_key() {
        let cipher = apply(&binary_with_padding(), &[0x37], 0);
        let found = recover_keys(&cipher, 16, 5);
        assert_eq!(found[0].key, vec![0x37], "{found:?}");
        assert!(found[0].reason.contains("0x00") || found[0].reason.contains("zeros"), "{}", found[0].reason);
    }

    #[test]
    fn repeating_key_on_text_is_solved_in_phase() {
        let cipher = apply(TEXT.as_bytes(), b"SECRET", 0);
        let lengths = guess_key_lengths(&cipher, 16);
        assert_eq!(lengths[0].0, 6, "{lengths:?}");
        let found = recover_keys(&cipher, 16, 5);
        assert_eq!(found[0].key, b"SECRET".to_vec(), "{found:?}");
    }

    #[test]
    fn repeating_key_is_read_from_a_zero_run() {
        let key = [0x13, 0x37, 0xC0, 0xDE, 0x42, 0x99, 0x05];
        let plain = binary_with_padding();
        let cipher = apply(&plain, &key, 0);
        let found = recover_keys(&cipher, 32, 5);
        assert_eq!(found[0].key, key.to_vec(), "{found:?}");
        assert_eq!(apply(&cipher, &found[0].key, 0), plain);
    }

    /// The report hidden in the DNS exfiltration challenge's loot.bin.
    const SHORT_REPORT: &str = "NIGHT OWL - staging report\n==========================\nTarget: payroll export for Q3, all cost centres.\n\
Archive split in two halves so that neither channel carries the whole file.\nHalf one went out over DNS TXT lookups, half two over the telemetry upload.\n\
Operator: remember to rotate the XOR key for the next job.\nProof of access: FLAG{owls_midnight_reunited_twice_9d82}\nEnd of report.\n";

    #[test]
    fn a_short_text_s_true_key_ranks_above_a_longer_key_that_repeats_it_with_a_column_wrong() {
        let key = [0x65, 0xFF, 0xB3, 0x35];
        let cipher = apply(SHORT_REPORT.as_bytes(), &key, 0);
        let found = recover_keys(&cipher, 32, 5);
        assert_eq!(found[0].key, key.to_vec(), "{found:?}");
        assert!(apply(&cipher, &found[0].key, 0).ends_with(b"FLAG{owls_midnight_reunited_twice_9d82}\nEnd of report.\n"));
        let longer = found.iter().find(|candidate| candidate.key.len() > key.len());
        assert!(longer.is_none_or(|candidate| candidate.key.len() % key.len() == 0), "the longer key is still offered: {found:?}");
    }

    #[test]
    fn sorting_the_keys_by_score_puts_them_in_the_order_they_are_proposed() {
        let key = [0x65, 0xFF, 0xB3, 0x35];
        let cipher = apply(SHORT_REPORT.as_bytes(), &key, 0);
        let found = recover_keys(&cipher, 32, 12);
        assert!(found.windows(2).all(|pair| pair[0].score >= pair[1].score), "a later key scores higher: {found:?}");
        let best = found.iter().max_by(|a, b| a.score.total_cmp(&b.score).then(b.key.len().cmp(&a.key.len()))).unwrap();
        assert_eq!(best.key, key.to_vec(), "{found:?}");
    }

    #[test]
    fn a_long_key_that_nearly_repeats_is_folded_to_its_period() {
        let key = b"SECRET";
        let cipher = apply(TEXT.as_bytes(), key, 0);
        let mut overfitted = key.repeat(4);
        overfitted[9] ^= 0x20;
        let (folded, agreeing) = fold_to_shorter_period(&cipher, &overfitted).expect("23 of 24 bytes repeat SECRET");
        assert_eq!((folded.as_slice(), agreeing), (key.as_slice(), 23));
        assert!(fold_to_shorter_period(&cipher, &key.repeat(2)).is_none(), "an exact repeat is folded by minimal_period already");
        assert!(fold_to_shorter_period(&cipher, b"SECRETsecret").is_none(), "half the bytes differ");
    }

    #[test]
    fn a_word_key_over_mostly_zeros_beats_a_single_byte_that_only_changes_its_case() {
        // Zeros XORed with "MODBUS" read "MODBUSMODBUS…"; a single-byte key
        // flipping its case reads "modbusmodbus…", which looks like letters
        // but is the key repeating, not text.
        // A dark picture: a bit over half zeros, the rest dim pixel values.
        let mut plain = b"BM6\xeb\x00\x00\x00\x00\x00\x006\x00\x00\x00(\x00".to_vec();
        plain.extend(std::iter::repeat_n(0u8, 480));
        plain.extend(noise(9000, 9).into_iter().map(|byte| if byte < 140 { 0 } else { byte % 40 }));
        let cipher = apply(&plain, b"MODBUS", 0);
        let found = recover_keys(&cipher, 32, 5);
        assert_eq!(found[0].key, b"MODBUS".to_vec(), "{found:?}");
        assert!(found[0].preview.starts_with("BM6"), "{}", found[0].preview);
    }

    #[test]
    fn apply_is_its_own_inverse_and_inputs_never_panic() {
        let data = noise(1000, 1);
        assert_eq!(apply(&apply(&data, b"key", 2), b"key", 2), data);
        assert_eq!(apply(&data, &[], 0), data);
        assert!(recover_keys(&[], 8, 5).is_empty());
        assert!(!recover_keys(&[1], 8, 5).is_empty());
        assert!(guess_key_lengths(&[1, 2, 3], 8).iter().all(|&(len, _)| len <= 1));
        assert_eq!(minimal_period(b"ABABAB"), b"AB".to_vec());
    }
}
