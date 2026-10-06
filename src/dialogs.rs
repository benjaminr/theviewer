//! Native open and save dialogs that do not block the window.
//!
//! A blocking dialog (`rfd::FileDialog`) runs the system panel's own modal
//! loop from inside a frame, which on macOS leaves the panel sluggish to
//! highlight and pick files. The asynchronous dialog is shown as a sheet on
//! the window instead, while the app's event loop keeps running; a background
//! thread waits for the answer, and the app collects it on a later frame.
//!
//! A dialog stays the window's, but what is done with the chosen path can
//! be a method call ([`ViewerApp::save_dialog_then_call`]), so writing the
//! file goes through the API and is journalled like any other action.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::Context;
use rfd::AsyncFileDialog;
use serde_json::Value;

use crate::api::ApiError;
use crate::app::{DialogKind, FileAction, ViewerApp};

/// How often to look for an answer while a dialog is open.
const ANSWER_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// What the person chose in a dialog.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Chosen(PathBuf),
    Cancelled,
}

/// A dialog that is open, or has just been answered.
pub struct FileRequest {
    receiver: Receiver<Answer>,
}

impl FileRequest {
    /// Ask for an existing file to open.
    pub fn open(dialog: AsyncFileDialog) -> Self {
        Self::spawn(move || pollster::block_on(dialog.pick_file()))
    }

    /// Ask where to save a file.
    pub fn save(dialog: AsyncFileDialog) -> Self {
        Self::spawn(move || pollster::block_on(dialog.save_file()))
    }

    /// A request that has already been answered, for tests.
    pub fn answered(answer: Answer) -> Self {
        let (sender, receiver) = mpsc::channel();
        let _ = sender.send(answer);
        FileRequest { receiver }
    }

    fn spawn(ask: impl FnOnce() -> Option<rfd::FileHandle> + Send + 'static) -> Self {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let answer = match ask() {
                Some(file) => Answer::Chosen(file.path().to_path_buf()),
                None => Answer::Cancelled,
            };
            let _ = sender.send(answer);
        });
        FileRequest { receiver }
    }

    /// The answer, once there is one. While the dialog is still open this
    /// asks for another frame soon, so the answer is picked up promptly.
    pub fn poll(&self, ctx: &Context) -> Option<Answer> {
        match self.receiver.try_recv() {
            Ok(answer) => Some(answer),
            Err(TryRecvError::Empty) => {
                ctx.request_repaint_after(ANSWER_POLL_INTERVAL);
                None
            }
            // The waiting thread ended without answering: treat it as cancelled.
            Err(TryRecvError::Disconnected) => Some(Answer::Cancelled),
        }
    }
}

impl ViewerApp {
    /// Ask where to save (the dialog titled `title`, suggesting
    /// `default_name`), then call `method` with `params` and the chosen path
    /// as `params[path_field]`, as the person's action: the dialog is the
    /// window's, the writing is the API's, so it is journalled.
    pub fn save_dialog_then_call(&mut self, title: &str, default_name: &str, method: &str, params: Value, path_field: &str) {
        let dialog = AsyncFileDialog::new().set_title(title).set_file_name(default_name);
        self.ask_for_file(DialogKind::Save, dialog, FileAction::Call { method: method.to_string(), params, path_field: path_field.to_string() });
    }

    /// Ask for a file to open (the dialog titled `title`), then call
    /// `method` with `params` and the chosen path as `params[path_field]`.
    pub fn open_dialog_then_call(&mut self, title: &str, method: &str, params: Value, path_field: &str) {
        let dialog = AsyncFileDialog::new().set_title(title);
        self.ask_for_file(DialogKind::Open, dialog, FileAction::Call { method: method.to_string(), params, path_field: path_field.to_string() });
    }

    /// Call `method` with `params` and `path` as `params[path_field]`, once a
    /// dialog has given the path; a failure is said on the status bar.
    pub(crate) fn call_with_chosen_path(&mut self, method: &str, mut params: Value, path_field: &str, path: &Path) -> Result<Value, ApiError> {
        let Some(fields) = params.as_object_mut() else {
            return Err(ApiError::invalid_params(format!("the parameters of {method} must be an object to take the chosen path as {path_field}")));
        };
        fields.insert(path_field.to_string(), Value::String(path.display().to_string()));
        self.perform(method, params)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::actions::take_performed;
    use crate::app::Launch;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        take_performed();
        app
    }

    #[test]
    fn a_chosen_path_is_put_in_the_call_s_params_and_the_call_made_as_the_person() {
        let path = std::env::temp_dir().join(format!("theviewer-dialog-call-{}.bin", std::process::id()));
        let mut app = app_with(b"abc");
        app.call_with_chosen_path("documents.save", json!({"doc": "current"}), "path", &path).unwrap();
        assert_eq!(take_performed(), [("documents.save".to_string(), json!({"doc": "current", "path": path.display().to_string()}))]);
        assert_eq!(std::fs::read(&path).unwrap(), b"abc");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_call_that_fails_after_the_dialog_says_why_on_the_status_bar() {
        let mut app = app_with(b"abc");
        let refused = app.call_with_chosen_path("documents.save", json!({"doc": "doc-9"}), "path", Path::new("/no/such/dir/x.bin")).unwrap_err();
        assert_eq!(refused.code, crate::api::ErrorCode::NotFound);
        assert!(app.status.contains("doc-9"), "{}", app.status);
        assert!(app.call_with_chosen_path("documents.save", json!([]), "path", Path::new("/no/such/dir/x.bin")).is_err(), "params must be an object");
        assert!(take_performed().len() == 1, "only the call with an object was made");
    }
}
