//! Who is calling the API, and whether they may change anything.
//!
//! Every call names its [`Caller`]. Panels, the palette and the menus are
//! the person at the keyboard and edit freely. Anyone else (a plugin, Ask,
//! an MCP client, the command line) is checked before a method that edits
//! the document or changes the view: each client has a [`Policy`], kept in
//! the preferences and chosen in Settings, that always allows, always asks
//! or never allows. A client not seen before is asked about.
//!
//! The check itself is [`decide`]; the workspace applies it
//! ([`super::Workspace::permission`]). The window holds a call that needs
//! asking about as a [`HeldCall`] and shows a confirmation window; a
//! headless workspace works on files its client opened, so it allows every
//! call.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ApiError, Effect, ErrorCode, Workspace};

/// Who made a call, which decides whether it may edit and what its edits
/// are labelled with.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Caller {
    /// The person, through panels, the palette, menus and shortcuts.
    Panel,
    /// A Lua plugin, by its file name (`sync_word.lua`).
    Plugin(String),
    /// Ask, the assistant.
    Ask,
    /// An MCP client, by the name it gave (`claude-code`).
    Mcp(String),
    /// `theviewer api` on the command line.
    Cli,
    /// A recipe being run, by its name (`Telemetry frames`), from the
    /// History tab, `theviewer replay` or `recipes.run`.
    Recipe(String),
}

impl Caller {
    /// The producer id its edits and messages are published as:
    /// `panel`, `plugin:sync_word.lua`, `ask`, `mcp:claude-code`, `cli`
    /// or `recipe:Telemetry frames`.
    pub fn producer(&self) -> String {
        match self {
            Caller::Panel => "panel".to_string(),
            Caller::Plugin(name) => format!("plugin:{name}"),
            Caller::Ask => "ask".to_string(),
            Caller::Mcp(name) => format!("mcp:{name}"),
            Caller::Cli => "cli".to_string(),
            Caller::Recipe(name) => format!("recipe:{name}"),
        }
    }

    /// The caller a producer id names, as the journal keeps it; an id of no
    /// known kind is taken as a plugin's.
    pub fn from_producer(producer: &str) -> Caller {
        match producer.split_once(':') {
            None if producer == "panel" => Caller::Panel,
            None if producer == "ask" => Caller::Ask,
            None if producer == "cli" => Caller::Cli,
            Some(("plugin", name)) => Caller::Plugin(name.to_string()),
            Some(("mcp", name)) => Caller::Mcp(name.to_string()),
            Some(("recipe", name)) => Caller::Recipe(name.to_string()),
            _ => Caller::Plugin(producer.to_string()),
        }
    }

    /// The key its policy is kept under, the same as its producer id; the
    /// person at the keyboard has none.
    pub fn client(&self) -> Option<String> {
        (*self != Caller::Panel).then(|| self.producer())
    }

    /// What a step `action` taken by this caller is called in the undo
    /// history: "XOR by mcp:claude-code", or just "XOR" for the person,
    /// whose steps the Edit menu has always named by what they did.
    pub fn label(&self, action: &str) -> String {
        match self {
            Caller::Panel => action.to_string(),
            _ => format!("{action} by {}", self.producer()),
        }
    }

    /// The caller as the confirmation window and messages name it.
    pub fn describe(&self) -> String {
        match self {
            Caller::Panel => "You".to_string(),
            Caller::Plugin(name) => format!("The plugin {name}"),
            Caller::Ask => "Ask".to_string(),
            Caller::Mcp(name) => format!("The MCP client {name}"),
            Caller::Cli => "The command line".to_string(),
            Caller::Recipe(name) => format!("The recipe {name}"),
        }
    }
}

impl fmt::Display for Caller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.producer())
    }
}

/// What a client may do without asking.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// Edit and change the view without asking.
    Allow,
    /// Ask the person each time.
    #[default]
    Ask,
    /// Never edit or change the view; reading is still allowed.
    Deny,
}

impl Policy {
    pub const ALL: [Policy; 3] = [Policy::Allow, Policy::Ask, Policy::Deny];

    /// The choice as Settings shows it.
    pub fn label(self) -> &'static str {
        match self {
            Policy::Allow => "Always allow",
            Policy::Ask => "Always ask",
            Policy::Deny => "Never allow",
        }
    }
}

/// The policy chosen for each client, by its key ([`Caller::client`]).
pub type Policies = BTreeMap<String, Policy>;

/// Whether one call may go ahead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// The person must be asked first.
    NeedsConfirmation,
    Denied,
}

/// Whether a call still needs someone's leave to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consent<'a> {
    /// It is allowed already: the person allowed it (in the confirmation
    /// window, or by starting what makes it), or it runs inside a call that
    /// was allowed.
    Given,
    /// It is checked against this caller's policy: its own caller's, or
    /// that of whoever started the run it is part of.
    CheckedAs(&'a Caller),
}

/// Whether a method with `effect` may run for `caller` under `policies`:
/// reads always may, and the person at the keyboard may do anything.
pub fn decide(caller: &Caller, effect: Effect, policies: &Policies) -> Decision {
    if !needs_permission(effect) {
        return Decision::Allowed;
    }
    let Some(client) = caller.client() else { return Decision::Allowed };
    match policies.get(&client).copied().unwrap_or_default() {
        Policy::Allow => Decision::Allowed,
        Policy::Ask => Decision::NeedsConfirmation,
        Policy::Deny => Decision::Denied,
    }
}

/// Whether methods with `effect` are checked: those that edit the document
/// or change the view.
pub fn needs_permission(effect: Effect) -> bool {
    matches!(effect, Effect::Edit | Effect::View)
}

/// The error a call gets when its client is not allowed to make it.
pub fn denied(caller: &Caller, method: &str) -> ApiError {
    ApiError::new(
        ErrorCode::ReadOnly,
        format!("{} may not call {method}: its edits are set to never be allowed; change this under Settings › Permissions", caller.describe()),
    )
}

/// The error a call gets when the person declined it.
pub fn declined(caller: &Caller, method: &str) -> ApiError {
    ApiError::new(ErrorCode::ReadOnly, format!("The person declined {method} from {}; nothing was changed", caller.producer()))
}

/// The error a call gets when nobody answered the confirmation in time.
pub fn timed_out(caller: &Caller, method: &str, seconds: u64) -> ApiError {
    ApiError::new(
        ErrorCode::ReadOnly,
        format!("Nobody confirmed {method} from {} within {seconds} seconds, so it was refused and nothing was changed; ask again when the person is there", caller.producer()),
    )
}

/// The `data` of the error a call gets when it must be confirmed but the
/// way it came in cannot wait for an answer.
pub const NEEDS_CONFIRMATION: &str = "needs_confirmation";

/// The error a call gets when it must be confirmed and was not held for it.
pub fn needs_confirmation(caller: &Caller, method: &str) -> ApiError {
    ApiError::new(
        ErrorCode::ReadOnly,
        format!("{} needs the person's permission to call {method}; allow it under Settings › Permissions", caller.describe()),
    )
    .with_data(serde_json::json!({ "reason": NEEDS_CONFIRMATION }))
}

/// What to do with a held call's result once the person has decided.
pub type ReplyTo = Box<dyn FnOnce(&mut dyn Workspace, Result<Value, ApiError>)>;

/// A call waiting for the person to allow or deny it.
pub struct HeldCall {
    pub caller: Caller,
    pub method: String,
    pub params: Value,
    /// The change in plain words, such as "XOR 128 selected bytes with 5A".
    pub description: String,
    pub reply: ReplyTo,
}

impl fmt::Debug for HeldCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HeldCall").field("caller", &self.caller).field("method", &self.method).field("description", &self.description).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policies(entries: &[(&str, Policy)]) -> Policies {
        entries.iter().map(|(client, policy)| (client.to_string(), *policy)).collect()
    }

    #[test]
    fn reading_is_always_allowed_and_the_person_may_do_anything() {
        let everyone_denied = policies(&[("ask", Policy::Deny), ("mcp:claude-code", Policy::Deny)]);
        assert_eq!(decide(&Caller::Ask, Effect::Read, &everyone_denied), Decision::Allowed);
        assert_eq!(decide(&Caller::Panel, Effect::Edit, &everyone_denied), Decision::Allowed);
    }

    #[test]
    fn each_client_is_allowed_asked_or_denied_by_its_own_policy() {
        let chosen = policies(&[("mcp:claude-code", Policy::Allow), ("plugin:sync_word.lua", Policy::Deny)]);
        assert_eq!(decide(&Caller::Mcp("claude-code".into()), Effect::Edit, &chosen), Decision::Allowed);
        assert_eq!(decide(&Caller::Plugin("sync_word.lua".into()), Effect::View, &chosen), Decision::Denied);
        assert_eq!(decide(&Caller::Mcp("other".into()), Effect::Edit, &chosen), Decision::NeedsConfirmation, "a new client is asked about");
        assert_eq!(decide(&Caller::Ask, Effect::Edit, &chosen), Decision::NeedsConfirmation);
    }

    #[test]
    fn a_denied_call_says_who_was_refused_and_where_to_change_it() {
        let error = denied(&Caller::Mcp("claude-code".into()), "bytes.write");
        assert_eq!(error.code, ErrorCode::ReadOnly);
        assert!(error.message.contains("The MCP client claude-code may not call bytes.write"), "{}", error.message);
        assert!(error.message.contains("Settings › Permissions"), "{}", error.message);
    }

    #[test]
    fn callers_are_published_by_stable_ids() {
        assert_eq!(Caller::Plugin("sync_word.lua".into()).producer(), "plugin:sync_word.lua");
        assert_eq!(Caller::Mcp("claude-code".into()).to_string(), "mcp:claude-code");
        assert_eq!(Caller::Panel.client(), None);
        assert_eq!(Caller::Ask.client().as_deref(), Some("ask"));
        assert_eq!(Caller::Recipe("Telemetry frames".into()).producer(), "recipe:Telemetry frames");
    }

    #[test]
    fn a_caller_is_found_again_from_the_id_the_journal_keeps() {
        for caller in [Caller::Panel, Caller::Ask, Caller::Cli, Caller::Plugin("sync.lua".into()), Caller::Mcp("claude-code".into()), Caller::Recipe("Telemetry: frames".into())] {
            assert_eq!(Caller::from_producer(&caller.producer()), caller);
        }
    }
}
