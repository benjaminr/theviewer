//! `recipes.*`: saved analyses, listed, described and run on a document
//! (`recipes.list`, `recipes.describe`, `recipes.run`).
//!
//! Declared by the phase 7 foundation so its row in the method table is
//! already there; area B adds the methods (see
//! `docs/design/history-recipes.md`).

use super::workspace::Workspace;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    Vec::new()
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}
