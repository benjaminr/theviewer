//! Which MCP revisions the server speaks and what each request says about
//! itself.
//!
//! The server is *dual-era*. The current revision, 2026-07-28, is stateless:
//! every request carries its protocol version, client capabilities and,
//! usually, the client's name in `_meta`, and there is no handshake. Earlier
//! revisions (2025-11-25 back to 2024-11-05) begin with `initialize`, which
//! fixes the version, the client's name and its log level for the rest of
//! the process. A request that carries the modern `_meta` is served as the
//! current revision; any other is served under the revision `initialize`
//! agreed, and is refused before there is one.

use serde_json::{Map, Value, json};

use super::jsonrpc::{INVALID_PARAMS, RpcError, UNSUPPORTED_PROTOCOL_VERSION};

/// The current revision: per-request metadata, no handshake.
pub const MODERN_VERSION: &str = "2026-07-28";
/// Revisions that begin with `initialize`, newest first.
pub const LEGACY_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// The first revision with tool titles, output schemas and structured content.
const STRUCTURED_OUTPUT_SINCE: &str = "2025-06-18";

/// `_meta` keys of the current revision.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
pub const META_LOG_LEVEL: &str = "io.modelcontextprotocol/logLevel";
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
pub const META_SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";

/// What a client that gives no name is called in edit labels.
const UNNAMED_CLIENT: &str = "client";

/// Every revision this server speaks, newest first.
pub fn supported_versions() -> Vec<&'static str> {
    std::iter::once(MODERN_VERSION).chain(LEGACY_VERSIONS.iter().copied()).collect()
}

/// The revision to answer `initialize` with: the client's when this server
/// speaks it, otherwise the newest handshake revision, which the client may
/// then accept or disconnect over.
pub fn negotiate_legacy(requested: Option<&str>) -> &'static str {
    LEGACY_VERSIONS.iter().copied().find(|version| Some(*version) == requested).unwrap_or(LEGACY_VERSIONS[0])
}

/// Whether `version` has tool titles, output schemas and structured content.
/// Revision names are dates, so they order as text.
pub fn has_structured_output(version: &str) -> bool {
    version >= STRUCTURED_OUTPUT_SINCE
}

/// The severity of a log message, least severe first (RFC 5424's levels).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl Severity {
    const NAMES: [(&'static str, Severity); 8] = [
        ("debug", Severity::Debug),
        ("info", Severity::Info),
        ("notice", Severity::Notice),
        ("warning", Severity::Warning),
        ("error", Severity::Error),
        ("critical", Severity::Critical),
        ("alert", Severity::Alert),
        ("emergency", Severity::Emergency),
    ];

    pub fn named(name: &str) -> Option<Severity> {
        Self::NAMES.iter().find(|(known, _)| *known == name).map(|(_, severity)| *severity)
    }

    pub fn name(self) -> &'static str {
        Self::NAMES.iter().find(|(_, severity)| *severity == self).map_or("info", |(name, _)| name)
    }

    /// The level asked for in `value`, or an invalid-params error naming the levels.
    pub fn parse(value: &Value) -> Result<Severity, RpcError> {
        value.as_str().and_then(Severity::named).ok_or_else(|| {
            let names: Vec<&str> = Self::NAMES.iter().map(|(name, _)| *name).collect();
            RpcError::invalid_params(format!("{value} is not a log level; use one of {}", names.join(", ")))
        })
    }
}

/// What one request says about itself, or what `initialize` agreed.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestContext {
    /// The revision to answer in.
    pub version: &'static str,
    /// The client's name, made fit for edit labels (`claude-code`).
    pub client: String,
    /// The least severe log message the client wants with this request, if any.
    pub log_level: Option<Severity>,
}

impl RequestContext {
    /// Whether the request is of the current, stateless revision.
    pub fn is_modern(&self) -> bool {
        self.version == MODERN_VERSION
    }
}

/// The context a request of the current revision gives in its `_meta`:
/// `None` when it carries no protocol version (it may belong to a session
/// `initialize` began), an error when what it carries is not acceptable.
pub fn modern_context(params: &Map<String, Value>) -> Result<Option<RequestContext>, RpcError> {
    let Some(meta) = params.get("_meta").and_then(Value::as_object) else { return Ok(None) };
    let Some(requested) = meta.get(META_PROTOCOL_VERSION) else { return Ok(None) };
    if requested.as_str() != Some(MODERN_VERSION) {
        return Err(RpcError::new(UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version").with_data(json!({ "supported": supported_versions(), "requested": requested })));
    }
    if !meta.get(META_CLIENT_CAPABILITIES).is_some_and(Value::is_object) {
        return Err(RpcError::new(INVALID_PARAMS, format!("_meta needs \"{META_CLIENT_CAPABILITIES}\", an object, on every request")));
    }
    let log_level = meta.get(META_LOG_LEVEL).map(Severity::parse).transpose()?;
    let client = client_label(meta.get(META_CLIENT_INFO).and_then(|info| info["name"].as_str()));
    Ok(Some(RequestContext { version: MODERN_VERSION, client, log_level }))
}

/// A client's name as edit labels and permissions use it: lower case, with
/// anything but letters, digits, dots, dashes and underscores made a dash.
pub fn client_label(name: Option<&str>) -> String {
    let label: String = name
        .unwrap_or_default()
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let label = label.trim_matches('-');
    if label.is_empty() { UNNAMED_CLIENT.to_string() } else { label.to_string() }
}

/// The server's name and version.
pub fn server_info() -> Value {
    json!({ "name": "theviewer", "title": "theviewer binary viewer", "version": env!("CARGO_PKG_VERSION") })
}

/// What the server offers, the same in every revision.
pub fn capabilities() -> Value {
    json!({
        "tools": { "listChanged": true },
        "resources": { "subscribe": true, "listChanged": true },
        "prompts": { "listChanged": false },
        "logging": {},
    })
}

/// Guidance for the model on how to use the server.
pub const INSTRUCTIONS: &str = "theviewer inspects and edits binary files: the ones this server was started with, and any opened with documents_open. \
Documents are named by id (doc-1), by path, or \"current\". Start with analysis_overview for a map of a file, then findings_query, \
structure_parse and templates_apply for detail; bytes_read and bytes_hexdump show bytes. The API has more methods than the core \
ones listed as tools by default (bits, strings, checksums, crypto, firmware, packets and more): api_search finds them, api_describe \
gives one's parameters, and api_call calls it. Edits (bytes_write, bytes_replace, transform_apply, bytes.insert, bytes.delete) are \
each one undoable step: history_undo reverses them, and documents_save writes them to disk, which nothing else does. \
Resources under theviewer://doc/{id} give a document's info, bytes, findings and facts; theviewer://reference/{id} gives notes on \
formats and protocols.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::jsonrpc::INVALID_PARAMS;

    fn meta(fields: Value) -> Map<String, Value> {
        json!({ "_meta": fields }).as_object().unwrap().clone()
    }

    #[test]
    fn initialize_agrees_on_the_clients_revision_when_it_is_spoken_and_the_newest_otherwise() {
        assert_eq!(negotiate_legacy(Some("2025-06-18")), "2025-06-18");
        assert_eq!(negotiate_legacy(Some("2024-11-05")), "2024-11-05");
        assert_eq!(negotiate_legacy(Some("2099-01-01")), "2025-11-25");
        assert_eq!(negotiate_legacy(Some(MODERN_VERSION)), "2025-11-25", "the handshake belongs to the older revisions");
        assert_eq!(negotiate_legacy(None), "2025-11-25");
    }

    #[test]
    fn structured_output_arrived_in_2025_06_18() {
        assert!(has_structured_output(MODERN_VERSION));
        assert!(has_structured_output("2025-06-18"));
        assert!(!has_structured_output("2025-03-26"));
    }

    #[test]
    fn a_modern_request_names_its_version_capabilities_client_and_log_level() {
        let context = modern_context(&meta(json!({
            META_PROTOCOL_VERSION: MODERN_VERSION,
            META_CLIENT_CAPABILITIES: {},
            META_CLIENT_INFO: { "name": "Claude Code", "version": "2.0" },
            META_LOG_LEVEL: "warning",
        })))
        .unwrap()
        .unwrap();
        assert_eq!(context, RequestContext { version: MODERN_VERSION, client: "claude-code".into(), log_level: Some(Severity::Warning) });
        assert!(context.is_modern());
    }

    #[test]
    fn a_request_without_a_protocol_version_belongs_to_a_handshake_session() {
        assert_eq!(modern_context(&Map::new()).unwrap(), None);
        assert_eq!(modern_context(&meta(json!({ "progressToken": 1 }))).unwrap(), None);
    }

    #[test]
    fn an_unsupported_version_is_refused_with_the_versions_spoken() {
        let error = modern_context(&meta(json!({ META_PROTOCOL_VERSION: "1900-01-01", META_CLIENT_CAPABILITIES: {} }))).unwrap_err();
        assert_eq!(error.code, UNSUPPORTED_PROTOCOL_VERSION);
        let data = error.data.unwrap();
        assert_eq!(data["requested"], "1900-01-01");
        assert_eq!(data["supported"][0], MODERN_VERSION);
        assert!(data["supported"].as_array().unwrap().contains(&json!("2025-11-25")));
    }

    #[test]
    fn a_modern_request_without_capabilities_or_with_an_unknown_log_level_is_invalid() {
        let missing = modern_context(&meta(json!({ META_PROTOCOL_VERSION: MODERN_VERSION }))).unwrap_err();
        assert_eq!(missing.code, INVALID_PARAMS);
        let level = modern_context(&meta(json!({ META_PROTOCOL_VERSION: MODERN_VERSION, META_CLIENT_CAPABILITIES: {}, META_LOG_LEVEL: "loud" }))).unwrap_err();
        assert_eq!(level.code, INVALID_PARAMS);
    }

    #[test]
    fn client_names_become_labels_fit_for_the_undo_history() {
        assert_eq!(client_label(Some("Claude Desktop")), "claude-desktop");
        assert_eq!(client_label(Some("  mcp-inspector ")), "mcp-inspector");
        assert_eq!(client_label(Some("")), "client");
        assert_eq!(client_label(None), "client");
    }

    #[test]
    fn severities_order_from_debug_to_emergency() {
        assert!(Severity::Debug < Severity::Info && Severity::Error < Severity::Emergency);
        assert_eq!(Severity::named("notice"), Some(Severity::Notice));
        assert_eq!(Severity::Critical.name(), "critical");
        assert!(Severity::parse(&json!("verbose")).is_err());
    }
}
