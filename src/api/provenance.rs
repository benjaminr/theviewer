//! Methods that edit where a step's values came from: turning a recorded
//! literal into an anchor or a named parameter, so a recipe made from the
//! journal is portable. Named in the `history` namespace.
//!
//! Declared by the phase 7 foundation so its row in the method table is
//! already there; area C adds the methods (see
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
