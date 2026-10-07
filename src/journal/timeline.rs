//! The journal as a timeline the person moves along: undoing steps that
//! changed no bytes through their inverses, going back to step N, and what
//! happens to the steps after it.
//!
//! Area A builds this module (see `docs/design/history-recipes.md`); as a
//! child of [`super`], it may reach the journal's own fields.

use serde_json::Value;

use crate::api::Workspace;

/// What a call to `method` with `params` is about to replace, kept on its
/// journal entry so the step can be undone: `None` for methods the
/// timeline does not model. Area A fills this in.
pub(crate) fn state_before(_workspace: &mut dyn Workspace, _method: &str, _params: &Value) -> Option<Value> {
    None
}
