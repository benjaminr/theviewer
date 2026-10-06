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
        let result = api::call(self, &Caller::Panel, method, params);
        if let Err(error) = &result {
            self.status = status_for(error);
        }
        result
    }

    /// [`ViewerApp::perform`] with typed parameters and result: the
    /// method's own params struct (or `json!`), and its result struct.
    pub fn perform_typed<R: DeserializeOwned>(&mut self, method: &str, params: impl Serialize) -> Result<R, ApiError> {
        let params = serde_json::to_value(params).map_err(|error| ApiError::invalid_params(format!("the parameters of {method} could not be written as JSON: {error}")))?;
        let result = self.perform(method, params)?;
        serde_json::from_value(result).map_err(|error| ApiError::invalid_params(format!("the result of {method} was not what the window expected: {error}")))
    }
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
    fn a_typed_action_returns_the_method_s_own_result() {
        let mut app = app_with(&[0u8; 8]);
        let result: EditResult = app.perform_typed("transform.apply", json!({"selection": {"range": [0, 4]}, "operation": {"op": "invert"}})).unwrap();
        assert_eq!((result.label.as_str(), result.ranges.as_slice()), ("Invert", &[(0, 4)][..]));
        assert_eq!(app.document.read_range(0, 5), [0xFF, 0xFF, 0xFF, 0xFF, 0]);
    }
}
