//! The analysis tools' own methods: what the person does in the Templates,
//! Columns, Protocol, Learn, Report, Structure map, Statistics, Strings,
//! XOR, Crypto, Checksums, Firmware, Images, Forensics, Compare, Trigrams,
//! Dot plot, Size map, Bits, Characterise and Reference tools, each under
//! the tool's own namespace (`strings.find`, `xor.recover_keys`…).
//! Methods over the whole document that any tool may use are in
//! [`super::analysis`].
//!
//! The tools' panels call these methods as `Caller::Panel` (see
//! `ViewerApp::perform`), so what the person does in a tool can be
//! journalled and replayed; see `docs/design/ui-actions.md`.

use super::workspace::Workspace;

mod join;
pub(crate) mod tool_jobs;
pub mod statistics;
pub mod strings;
pub mod xor;
pub mod checksums;
pub mod diff;
pub mod disasm;
pub mod crypto;
pub mod bits;
pub mod compare;
pub mod dotplot;
pub mod images;
pub mod trigrams;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &join::join::<{ statistics::METHODS.len() + strings::METHODS.len() + xor::METHODS.len() + checksums::METHODS.len() + diff::METHODS.len() + disasm::METHODS.len() + crypto::METHODS.len() + bits::METHODS.len() + compare::METHODS.len() + dotplot::METHODS.len() + images::METHODS.len() + trigrams::METHODS.len() }>(&[statistics::METHODS, strings::METHODS, xor::METHODS, checksums::METHODS, diff::METHODS, disasm::METHODS, crypto::METHODS, bits::METHODS, compare::METHODS, dotplot::METHODS, images::METHODS, trigrams::METHODS]);

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    [statistics::examples(), strings::examples(), xor::examples(), checksums::examples(), diff::examples(), disasm::examples(), crypto::examples(), bits::examples(), compare::examples(), dotplot::examples(), images::examples(), trigrams::examples()].concat()
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    disasm::describe_call(workspace, method, params)
}
