//! The person's actions, carried out through the data API.
//!
//! Every action in the window (a menu item, a shortcut, a palette command,
//! the context menu, a toolbar button, a panel's button) that changes the
//! document, the analysis or the view's shape calls a method as
//! `Caller::Panel` through [`ViewerApp::perform`], the same way plugins,
//! Ask and MCP clients do. Nothing the person does then bypasses the API,
//! so an analysis can be journalled, replayed and saved as a recipe.
//!
//! An action's parameters carry everything needed to repeat it (the
//! selection it acted on, the width it set, how a set was split), never
//! state the method would read silently from a panel.
//! `docs/design/ui-actions.md` lists every action with its method.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::api::{self, ApiError, Caller};
use crate::app::ViewerApp;

impl ViewerApp {
    /// Do what the person asked for by calling `method` with `params` as
    /// `Caller::Panel`, and return its result (the ids of what it made,
    /// such as a packet set or a job, for later steps). When the call
    /// fails, the status bar says why, as the app's own messages do; a
    /// caller with a better place for the error (a panel's note) may show
    /// it there too.
    pub fn perform(&mut self, method: &str, params: Value) -> Result<Value, ApiError> {
        #[cfg(test)]
        PERFORMED.with_borrow_mut(|performed| performed.push((method.to_string(), params.clone())));
        let result = api::call(self, &Caller::Panel, method, params);
        if let Err(error) = &result {
            self.status = status_for(error);
        }
        result
    }

    /// [`ViewerApp::perform`], noting where the values of some parameters
    /// came from (a split started from a search match records that match),
    /// by parameter path, so the journal entry carries them as
    /// `derived_from` and a recipe made from it is portable.
    /// A read an anchor cites (the keys `xor.recover_keys` proposed, say)
    /// is moved into the journal first, so a recipe holds it.
    pub fn perform_derived(&mut self, method: &str, params: Value, derived_from: crate::journal::DerivedFrom) -> Result<Value, ApiError> {
        self.promote_cited_reads(&derived_from);
        self.with_provenance(derived_from, |app| app.perform(method, params))
    }

    /// Move the reads `derived_from`'s anchors cite into the journal.
    fn promote_cited_reads(&mut self, derived_from: &crate::journal::DerivedFrom) {
        let sheets = crate::journal::anchors::RunSheets::default();
        let cited: Vec<u64> = derived_from.values().flat_map(|anchor| anchor.cited_steps(&sheets)).collect();
        for step in cited {
            if self.journal.entry(step).is_none() {
                crate::journal::promote(self, step);
            }
        }
    }

    /// [`ViewerApp::perform`] once the frame's drawing is over: for a panel
    /// drawn with its state lent out (`panels::show`, `panels::with`), whose
    /// action calls a method that writes that same state (a packet set
    /// shown in the Packets panel, say), which would otherwise land on the
    /// placeholder and be lost. The result is not returned; a failure is
    /// said on the status bar.
    pub fn perform_later(&mut self, method: &str, params: Value) {
        self.perform_later_derived(method, params, crate::journal::DerivedFrom::new());
    }

    /// [`ViewerApp::perform_later`] for a call whose parameters came from
    /// earlier results, as [`ViewerApp::perform_derived`] records them.
    pub fn perform_later_derived(&mut self, method: &str, params: Value, derived_from: crate::journal::DerivedFrom) {
        self.actions_after_drawing.push((method.to_string(), params, derived_from));
    }

    /// Carry out the actions [`ViewerApp::perform_later`] kept, in order.
    pub(crate) fn perform_waiting_actions(&mut self) {
        crate::send_to::send_waiting(self);
        for (method, params, derived_from) in std::mem::take(&mut self.actions_after_drawing) {
            let _ = self.perform_derived(&method, params, derived_from);
        }
    }

    /// [`ViewerApp::perform`] with typed parameters and result: the
    /// method's own params struct (or `json!`), and its result struct.
    pub fn perform_typed<R: DeserializeOwned>(&mut self, method: &str, params: impl Serialize) -> Result<R, ApiError> {
        let params = serde_json::to_value(params).map_err(|error| ApiError::invalid_params(format!("the parameters of {method} could not be written as JSON: {error}")))?;
        let result = self.perform(method, params)?;
        serde_json::from_value(result).map_err(|error| ApiError::invalid_params(format!("the result of {method} was not what the window expected: {error}")))
    }
}

#[cfg(test)]
thread_local! {
    /// The calls [`ViewerApp::perform`] made on this thread, for tests.
    static PERFORMED: std::cell::RefCell<Vec<(String, Value)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The methods the person's actions called on this thread since the last
/// time this was asked, with their parameters: how a test proves an action
/// went through the API, and with everything needed to repeat it.
#[cfg(test)]
pub fn take_performed() -> Vec<(String, Value)> {
    PERFORMED.with_borrow_mut(std::mem::take)
}

/// A failed call as the status bar says it: the message, starting with a
/// capital letter like the app's own.
fn status_for(error: &ApiError) -> String {
    let mut characters = error.message.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().chain(characters).collect(),
        None => format!("{error}"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::api::edits::EditResult;
    use crate::app::Launch;
    use crate::bus::Topic;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        app
    }

    #[test]
    fn an_action_is_carried_out_through_the_api_as_the_person() {
        let mut app = app_with(b"0123456789");
        let cursor = app.bus.cursor();
        let written = app.perform("bytes.write", json!({"start": 2, "data": "4142"})).unwrap();
        assert_eq!(written["label"], "Overwrite 2 bytes", "the person's steps are named by what they did");
        app.run_bus();
        let edited = app.bus.changed_since(cursor).messages.into_iter().find(|message| message.topic() == Topic::DocumentEdited).expect("the edit is published");
        assert_eq!(edited.producer(), "panel");
        assert_eq!(app.document.read_range(0, 10), b"01AB456789");
        assert_eq!(app.document.undo_label(), Some("Overwrite 2 bytes"));
        assert_eq!(take_performed(), [("bytes.write".to_string(), json!({"start": 2, "data": "4142"}))], "a test can see what was performed");
        assert!(take_performed().is_empty());
    }

    #[test]
    fn a_failed_action_says_why_on_the_status_bar() {
        let mut app = app_with(b"abc");
        let error = app.perform("bytes.write", json!({"start": 2, "data": "0000"})).unwrap_err();
        assert_eq!(error.code, api::ErrorCode::OutOfRange);
        assert!(app.status.contains("run past the end of the document"), "{}", app.status);
        assert_eq!(app.document.read_range(0, 3), b"abc");
    }

    #[test]
    fn an_action_asked_for_while_drawing_is_carried_out_before_the_next_frame() {
        let mut app = app_with(b"0123");
        app.perform_later("bytes.write", json!({"start": 0, "data": "41"}));
        assert_eq!(app.document.read_range(0, 1), b"0", "nothing happens while drawing");
        assert!(take_performed().is_empty());
        app.perform_waiting_actions();
        assert_eq!(app.document.read_range(0, 1), b"A");
        assert_eq!(take_performed().len(), 1);
    }

    #[test]
    fn a_typed_action_returns_the_method_s_own_result() {
        let mut app = app_with(&[0u8; 8]);
        let result: EditResult = app.perform_typed("transform.apply", json!({"selection": {"range": [0, 4]}, "operation": {"op": "invert"}})).unwrap();
        assert_eq!((result.label.as_str(), result.ranges.as_slice()), ("Invert", &[(0, 4)][..]));
        assert_eq!(app.document.read_range(0, 5), [0xFF, 0xFF, 0xFF, 0xFF, 0]);
    }
}
