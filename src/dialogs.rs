//! Native open and save dialogs that do not block the window.
//!
//! A blocking dialog (`rfd::FileDialog`) runs the system panel's own modal
//! loop from inside a frame, which on macOS leaves the panel sluggish to
//! highlight and pick files. The asynchronous dialog is shown as a sheet on
//! the window instead, while the app's event loop keeps running; a background
//! thread waits for the answer, and the app collects it on a later frame.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::Context;
use rfd::AsyncFileDialog;

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
