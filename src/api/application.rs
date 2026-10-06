//! The application around the documents: plugins (`plugins.*`), settings
//! and media (`media.*`), for the person's actions that change neither the
//! bytes nor the view's shape but still belong in a recorded analysis
//! (reloading the plugins it used, say).
//!
//! See `docs/design/ui-actions.md`.

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
