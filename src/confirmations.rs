//! Asking the person before a plugin, Ask or another client changes the
//! document or the view.
//!
//! A call whose client's policy is "always ask" is held here, and a window
//! shows who wants to do what, in plain words, with three answers: allow it
//! once, always allow that client (which changes its policy in Settings),
//! or deny it. Nothing blocks while it waits: the call's reply runs when
//! the person answers, or, after [`CONFIRMATION_TIMEOUT`] with no answer,
//! the call is refused with a message saying so. Calls are answered in the
//! order they arrived.
//!
//! This is how every caller that cannot wait on the UI thread asks: Ask's
//! tool calls (whose worker thread waits for the reply), plugins' handlers
//! and, later, MCP requests all go through [`ViewerApp::request_api_call`].

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use eframe::egui::{self, Context, RichText};
use serde_json::Value;

use crate::api::permissions::{self, Policy, ReplyTo};
use crate::api::{self, ApiError, Caller, HeldCall};
use crate::app::ViewerApp;
use crate::theme;

/// How long a held call waits for an answer before it is refused.
pub const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(120);

/// One held call and when it arrived.
#[derive(Debug)]
struct Waiting {
    call: HeldCall,
    since: Instant,
}

/// The calls waiting for the person, oldest first.
#[derive(Debug, Default)]
pub struct Confirmations {
    waiting: VecDeque<Waiting>,
}

impl Confirmations {
    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// The call the window asks about: the oldest.
    pub fn current(&self) -> Option<&HeldCall> {
        self.waiting.front().map(|waiting| &waiting.call)
    }
}

/// The person's answer to a held call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    AllowOnce,
    /// Allow this call and every later one from the same client.
    AlwaysAllow,
    Deny,
}

impl ViewerApp {
    /// Run `method` for `caller` if its policy allows, refuse it if denied,
    /// and otherwise hold it for the person; `reply` gets the result either
    /// way. The way in for callers that cannot block the window.
    pub fn request_api_call(&mut self, caller: Caller, method: &str, params: Value, reply: ReplyTo) {
        api::call_or_hold(self, caller, method, params, reply);
    }

    /// Hold `call` until the person answers; a client seen for the first
    /// time is added to Settings, set to ask.
    pub(crate) fn hold_call(&mut self, call: HeldCall) {
        if let Some(client) = call.caller.client()
            && !self.preferences.permissions.contains_key(&client)
        {
            let mut preferences = self.preferences.clone();
            preferences.permissions.insert(client, Policy::Ask);
            self.set_preferences(preferences);
        }
        self.status = format!("{} asks to: {}", call.caller.describe(), call.description);
        self.confirmations.waiting.push_back(Waiting { call, since: Instant::now() });
    }

    /// Answer the oldest held call.
    pub fn answer_confirmation(&mut self, answer: Answer) {
        let Some(Waiting { call, .. }) = self.confirmations.waiting.pop_front() else { return };
        let HeldCall { caller, method, params, description, reply } = call;
        let result = match answer {
            Answer::Deny => {
                self.status = format!("Declined: {description}");
                Err(permissions::declined(&caller, &method))
            }
            Answer::AllowOnce | Answer::AlwaysAllow => {
                if answer == Answer::AlwaysAllow
                    && let Some(client) = caller.client()
                {
                    let mut preferences = self.preferences.clone();
                    preferences.permissions.insert(client, Policy::Allow);
                    self.set_preferences(preferences);
                }
                let result = api::call_permitted(self, &caller, &method, params);
                self.status = match &result {
                    Ok(_) => format!("Allowed: {description}"),
                    Err(error) => format!("{description} failed: {}", error.message),
                };
                result
            }
        };
        reply(self, result);
    }

    /// Refuse the held calls nobody answered in time.
    pub fn expire_confirmations(&mut self) {
        self.expire_confirmations_older_than(CONFIRMATION_TIMEOUT);
    }

    /// Refuse the held calls that have waited longer than `limit`.
    pub fn expire_confirmations_older_than(&mut self, limit: Duration) {
        while let Some(waiting) = self.confirmations.waiting.front()
            && waiting.since.elapsed() >= limit
        {
            let Some(Waiting { call, .. }) = self.confirmations.waiting.pop_front() else { break };
            self.status = format!("Refused, as nobody answered: {}", call.description);
            let error: ApiError = permissions::timed_out(&call.caller, &call.method, limit.as_secs());
            (call.reply)(self, Err(error));
        }
    }

    /// The window asking about the oldest held call.
    pub fn show_confirmation_window(&mut self, ctx: &Context) {
        self.expire_confirmations();
        let Some(waiting) = self.confirmations.waiting.front() else { return };
        let call = &waiting.call;
        let left = CONFIRMATION_TIMEOUT.saturating_sub(waiting.since.elapsed());
        let who = call.caller.describe();
        let client = call.caller.producer();
        let description = call.description.clone();
        let method = call.method.clone();
        let more = self.confirmations.len() - 1;
        let mut answer = None;
        egui::Window::new("Allow this change?")
            .collapsible(false)
            .resizable(false)
            .default_width(460.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(RichText::new(format!("{who} wants to change the document:")).strong());
                ui.add_space(4.0);
                ui.label(RichText::new(&description).monospace());
                ui.add_space(4.0);
                ui.label(RichText::new(format!("Method {method}, from {client}. Every change can be undone.")).small().color(theme::TEXT_DIM));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Allow once").clicked() {
                        answer = Some(Answer::AllowOnce);
                    }
                    if ui.button("Always allow this client").on_hover_text(format!("Let {client} edit without asking; change this under Settings › Permissions")).clicked() {
                        answer = Some(Answer::AlwaysAllow);
                    }
                    if ui.button("Deny").clicked() {
                        answer = Some(Answer::Deny);
                    }
                });
                ui.add_space(4.0);
                let mut footnote = format!("Refused automatically in {} s if nobody answers.", left.as_secs());
                if more > 0 {
                    footnote.push_str(&format!(" {more} more waiting."));
                }
                ui.label(RichText::new(footnote).small().color(theme::TEXT_DIM));
            });
        if let Some(answer) = answer {
            self.answer_confirmation(answer);
        }
        // Count down, and refuse on time, without waiting for input.
        ctx.request_repaint_after(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use serde_json::json;

    use super::*;
    use crate::api::ErrorCode;
    use crate::app::Launch;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app
    }

    /// A reply that sends the result down a channel, as Ask's does.
    fn channel_reply() -> (ReplyTo, mpsc::Receiver<Result<Value, ApiError>>) {
        let (sender, receiver) = mpsc::channel();
        (Box::new(move |_, result| drop(sender.send(result))), receiver)
    }

    #[test]
    fn an_edit_from_ask_waits_for_the_person_and_is_applied_when_allowed() {
        let mut app = app_with(&[0u8; 8]);
        let (reply, answers) = channel_reply();
        app.request_api_call(Caller::Ask, "bytes.write", json!({"start": 2, "data": "dead"}), reply);
        assert_eq!(app.confirmations.len(), 1);
        assert_eq!(app.confirmations.current().unwrap().description, "Overwrite 2 bytes at 0x2 with DE AD");
        assert!(answers.try_recv().is_err(), "nothing is answered yet");
        assert_eq!(app.document.read_range(0, 8), [0; 8]);
        assert_eq!(app.preferences.permissions.get("ask"), Some(&Policy::Ask), "Ask is listed in Settings");

        app.answer_confirmation(Answer::AllowOnce);
        assert!(answers.try_recv().unwrap().is_ok());
        assert_eq!(app.document.read_range(0, 4), [0, 0, 0xDE, 0xAD]);
        assert_eq!(app.document.undo_label(), Some("Overwrite 2 bytes by ask"));
        assert_eq!(app.preferences.permissions.get("ask"), Some(&Policy::Ask), "allowing once changes no setting");
    }

    #[test]
    fn a_denied_edit_changes_nothing_and_says_the_person_declined() {
        let mut app = app_with(&[0u8; 8]);
        let (reply, answers) = channel_reply();
        app.request_api_call(Caller::Mcp("claude-code".into()), "bytes.delete", json!({"start": 0, "len": 4}), reply);
        app.answer_confirmation(Answer::Deny);
        let error = answers.try_recv().unwrap().unwrap_err();
        assert_eq!(error.code, ErrorCode::ReadOnly);
        assert!(error.message.contains("declined"), "{}", error.message);
        assert_eq!(app.document.len(), 8);
    }

    #[test]
    fn always_allowing_a_client_lets_its_next_edit_through_without_asking() {
        let mut app = app_with(&[0u8; 8]);
        let (reply, answers) = channel_reply();
        app.request_api_call(Caller::Ask, "bytes.write", json!({"start": 0, "data": "01"}), reply);
        app.answer_confirmation(Answer::AlwaysAllow);
        assert!(answers.try_recv().unwrap().is_ok());
        assert_eq!(app.preferences.permissions.get("ask"), Some(&Policy::Allow));
        let (reply, answers) = channel_reply();
        app.request_api_call(Caller::Ask, "bytes.write", json!({"start": 1, "data": "02"}), reply);
        assert!(app.confirmations.is_empty());
        assert!(answers.try_recv().unwrap().is_ok());
        assert_eq!(app.document.read_range(0, 2), [1, 2]);
    }

    #[test]
    fn a_client_set_to_never_is_refused_at_once_and_reading_is_never_asked_about() {
        let mut app = app_with(&[0u8; 8]);
        app.preferences.permissions.insert("mcp:rogue".into(), Policy::Deny);
        let (reply, answers) = channel_reply();
        app.request_api_call(Caller::Mcp("rogue".into()), "bytes.insert", json!({"at": 0, "data": "00"}), reply);
        assert!(app.confirmations.is_empty());
        assert!(answers.try_recv().unwrap().unwrap_err().message.contains("never be allowed"));
        let (reply, answers) = channel_reply();
        app.request_api_call(Caller::Mcp("rogue".into()), "bytes.read", json!({"start": 0, "len": 2}), reply);
        assert_eq!(answers.try_recv().unwrap().unwrap()["data"], "0000");
    }

    #[test]
    fn a_call_nobody_answers_is_refused_with_a_clear_message() {
        let mut app = app_with(&[0u8; 8]);
        let (reply, answers) = channel_reply();
        app.request_api_call(Caller::Ask, "bytes.write", json!({"start": 0, "data": "01"}), reply);
        app.expire_confirmations_older_than(Duration::ZERO);
        let error = answers.try_recv().unwrap().unwrap_err();
        assert!(error.message.contains("Nobody confirmed bytes.write from ask"), "{}", error.message);
        assert!(app.confirmations.is_empty());
        assert_eq!(app.document.read_range(0, 1), [0]);
    }
}
