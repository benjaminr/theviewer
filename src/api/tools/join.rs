//! Joining the tools' method lists into the one list `tools` declares.

use crate::api::Method;

/// The methods of `parts`, in order, as one array of `N` methods; `N` must
/// be the sum of the parts' lengths, and at least one.
pub(crate) const fn join<const N: usize>(parts: &[&[Method]]) -> [Method; N] {
    let mut first = 0;
    while parts[first].is_empty() {
        first += 1;
    }
    let mut joined = [parts[first][0]; N];
    let mut filled = 0;
    let mut part = 0;
    while part < parts.len() {
        let mut index = 0;
        while index < parts[part].len() {
            joined[filled] = parts[part][index];
            filled += 1;
            index += 1;
        }
        part += 1;
    }
    assert!(filled == N, "N must be the number of methods in the parts");
    joined
}
