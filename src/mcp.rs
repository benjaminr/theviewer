//! The MCP server: `theviewer mcp [FILE…]` speaks the Model Context
//! Protocol over standard input and output, so Claude Code, Claude Desktop
//! and other MCP clients can inspect and edit the files it was given.
//!
//! Every API method, the plugins' included, is a tool; documents, their
//! bytes, findings and facts, and the reference notes are resources, whose
//! subscribers hear of changes from the workspace bus; and a few prompts
//! walk a model through the tools. It is hand-written, synchronous
//! JSON-RPC: one thread handles messages in turn, another reads them.
//!
//! It works on a [`HeadlessWorkspace`] of the files given (and any opened
//! with `documents.open`), which allows every call: they are the client's
//! own files. Edits change only the open document until `documents.save`.
//! Messages go to standard output and nothing else does: logs go to
//! standard error.
//!
//! See `docs/design/shared-knowledge-and-api.md` ("MCP server").

pub mod jsonrpc;
pub mod prompts;
pub mod protocol;
pub mod resources;
pub mod server;
pub mod tools;

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::api::{HeadlessWorkspace, Workspace};
use crate::app;
use crate::plugins::LuaHost;
pub use server::Server;

/// How to start the server.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Options {
    /// Files to open, in order; the last is current.
    pub files: Vec<PathBuf>,
    /// Where to load plugins from, instead of the usual directories.
    pub plugin_dirs: Option<Vec<PathBuf>>,
}

/// A server with the plugins loaded and the files open. A file that cannot
/// be opened is an error, so a mistyped path is not served as nothing.
pub fn start(options: &Options) -> Result<Server, String> {
    let dirs = options.plugin_dirs.clone().unwrap_or_else(crate::plugins::default_dirs);
    let mut host = LuaHost::new();
    for dir in &dirs {
        for report in host.load_dir(dir) {
            if let Err(error) = report.result {
                eprintln!("theviewer mcp: plugin {} failed to load: {error}", report.name);
            }
        }
    }
    let methods = host.methods();
    let host = Arc::new(std::sync::Mutex::new(host));
    let mut workspace = HeadlessWorkspace::new(Arc::new(app::build_registry_with(Some(&host))));
    workspace.set_registered_methods(methods);
    for file in &options.files {
        workspace.open_path(file).map_err(|error| error.message)?;
    }
    Ok(Server::new(workspace, host))
}

/// Serve on standard input and output until the input closes.
pub fn run_stdio(options: &Options) -> Result<(), String> {
    let mut server = start(options)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    server::serve(&mut server, io::BufReader::new(io::stdin()), &mut output).map_err(|error| format!("could not write to the client: {error}"))
}
