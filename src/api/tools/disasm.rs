//! `disasm.set_arch`: which architecture the Disassembly tab decodes as.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::analysis_tabs::ArchChoice;
use crate::api::workspace::Workspace;
use crate::api::ApiError;
use crate::disasm::Arch;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[method!(
    "disasm.set_arch",
    View,
    set_arch,
    SetArchParams,
    SetArchResult,
    "Choose the architecture the Disassembly tab decodes as, or auto (the executable header's, else a guess from the bytes); headless there is no listing to change, and the choice is only returned."
)];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("disasm.set_arch", json!({"arch": "thumb"}))]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it.
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    let arch: DisasmArch = serde_json::from_value(params.get("arch")?.clone()).ok()?;
    (method == "disasm.set_arch").then(|| format!("Disassemble as {}", arch.label()))
}

/// An architecture the disassembler decodes, or auto.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisasmArch {
    /// The executable header's architecture, else a guess from the bytes.
    #[default]
    Auto,
    X86_64,
    X86_32,
    Arm64,
    Arm32,
    Thumb,
    Riscv64,
    Riscv32,
    Mips32,
    Powerpc32,
}

impl DisasmArch {
    /// The choice for the disassembler's `arch`.
    pub fn of(arch: Arch) -> Self {
        match arch {
            Arch::X86_64 => DisasmArch::X86_64,
            Arch::X86_32 => DisasmArch::X86_32,
            Arch::Arm64 => DisasmArch::Arm64,
            Arch::Arm32 => DisasmArch::Arm32,
            Arch::Thumb => DisasmArch::Thumb,
            Arch::RiscV64 => DisasmArch::Riscv64,
            Arch::RiscV32 => DisasmArch::Riscv32,
            Arch::Mips32 => DisasmArch::Mips32,
            Arch::PowerPc32 => DisasmArch::Powerpc32,
        }
    }

    /// The choice as the Disassembly tab holds it.
    pub fn choice(self) -> ArchChoice {
        let fixed = match self {
            DisasmArch::Auto => return ArchChoice::Auto,
            DisasmArch::X86_64 => Arch::X86_64,
            DisasmArch::X86_32 => Arch::X86_32,
            DisasmArch::Arm64 => Arch::Arm64,
            DisasmArch::Arm32 => Arch::Arm32,
            DisasmArch::Thumb => Arch::Thumb,
            DisasmArch::Riscv64 => Arch::RiscV64,
            DisasmArch::Riscv32 => Arch::RiscV32,
            DisasmArch::Mips32 => Arch::Mips32,
            DisasmArch::Powerpc32 => Arch::PowerPc32,
        };
        ArchChoice::Fixed(fixed)
    }

    /// The tab's choice as a parameter.
    pub fn of_choice(choice: ArchChoice) -> Self {
        match choice {
            ArchChoice::Auto => DisasmArch::Auto,
            ArchChoice::Fixed(arch) => DisasmArch::of(arch),
        }
    }

    pub fn label(self) -> &'static str {
        match self.choice() {
            ArchChoice::Auto => "Auto",
            ArchChoice::Fixed(arch) => arch.label(),
        }
    }
}

/// Parameters of `disasm.set_arch`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetArchParams {
    /// The architecture, such as "thumb" or "x86_64", or "auto".
    pub arch: DisasmArch,
}

/// The result of `disasm.set_arch`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SetArchResult {
    /// The architecture chosen.
    pub arch: DisasmArch,
    /// Whether a Disassembly tab was there to change (only in the window).
    pub shown: bool,
}

pub fn set_arch(workspace: &mut dyn Workspace, params: SetArchParams) -> Result<SetArchResult, ApiError> {
    let shown = match workspace.window() {
        Some(app) => {
            app.bench.analysis.arch = params.arch.choice();
            true
        }
        None => false,
    };
    Ok(SetArchResult { arch: params.arch, shown })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn choosing_an_architecture_headless_returns_it_without_a_listing_to_change() {
        let mut workspace = workspace_with("a.bin", b"code");
        assert_eq!(call(&mut workspace, "disasm.set_arch", json!({"arch": "riscv64"})).unwrap(), json!({"arch": "riscv64", "shown": false}));
        assert_eq!(call(&mut workspace, "disasm.set_arch", json!({"arch": "z80"})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn choosing_an_architecture_in_the_window_changes_the_disassembly() {
        let mut app = crate::app::ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(vec![0x90; 64], "code.bin".to_string());
        let chosen = crate::api::call(&mut app, &crate::api::Caller::Panel, "disasm.set_arch", json!({"arch": "thumb"})).unwrap();
        assert_eq!(chosen["shown"], true);
        assert_eq!(app.bench.analysis.arch, crate::analysis_tabs::ArchChoice::Fixed(crate::disasm::Arch::Thumb));
    }
}
