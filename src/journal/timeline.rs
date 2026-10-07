//! The journal as a timeline the person moves along: undoing steps that
//! changed no bytes through their inverses, going back to step N, and what
//! happens to the steps after it.
//!
//! Area A builds this module (see `docs/design/history-recipes.md`); as a
//! child of [`super`], it may reach the journal's own fields.
