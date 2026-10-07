//! Provenance: noting, while recording, where a step's values came from,
//! and editing it afterwards.
//!
//! A value the person took from a search match, a finding or an earlier
//! step's result is recorded as an [`super::Anchor`] in the step's
//! `derived_from`, through [`crate::api::call_derived`] or
//! `ViewerApp::perform_derived`, citing a read with [`super::promote`]
//! first. In the History tab any literal can be turned into an anchor or a
//! named parameter.
//!
//! Area C builds this module (see `docs/design/history-recipes.md`): the
//! capture at the call sites, the operations on a step's `derived_from`,
//! and the recipe made with anchors in place of literals.
