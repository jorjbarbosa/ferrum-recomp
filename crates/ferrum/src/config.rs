// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The TOML config of `ferrum recomp`. `docs/config.example.toml` documents every key.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ferrum_analysis::Function;
use ferrum_codegen::{Action, ControlFlow, DEFAULT_FUNCTIONS_PER_CRATE, Hooks, MidAsm, Override};
use serde::Deserialize;

/// A recompilation config, with its paths resolved against the directory of its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The XEX file to recompile.
    pub xex: PathBuf,
    /// The directory of the output workspace.
    pub out: PathBuf,
    /// The name of the root crate of the output.
    pub crate_name: String,
    /// How many functions each crate of the output holds.
    pub functions_per_crate: usize,
    /// The directory of `ferrum-runtime` the output depends on, if not the default one.
    pub runtime: Option<PathBuf>,
    /// `[analysis] functions`.
    pub functions: Vec<Function>,
    /// `[analysis] skip`.
    pub skip: Vec<Function>,
    /// `[analysis] jump_tables`: entry counts by the address of the `bctr`.
    pub table_entries: BTreeMap<u32, u32>,
    /// `[analysis] setjmp`.
    pub setjmp: Option<u32>,
    /// `[analysis] longjmp`.
    pub longjmp: Option<u32>,
    /// `[hooks]`.
    pub hooks: Hooks,
    /// `[optimizations] trap_as_nop`.
    pub trap_as_nop: bool,
    /// `[optimizations] control_flow`.
    pub control_flow: ControlFlow,
    /// `[optimizations] dispatch`: functions kept in dispatch form, by entry.
    pub dispatch: Vec<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    main: Main,
    #[serde(default)]
    analysis: Analysis,
    #[serde(default)]
    hooks: HookLists,
    #[serde(default)]
    optimizations: Optimizations,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Main {
    xex: PathBuf,
    out: PathBuf,
    crate_name: String,
    functions_per_crate: Option<usize>,
    runtime: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Analysis {
    #[serde(default)]
    functions: Vec<Span>,
    #[serde(default)]
    skip: Vec<Span>,
    #[serde(default)]
    jump_tables: Vec<TableCount>,
    setjmp: Option<u32>,
    longjmp: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Span {
    addr: u32,
    size: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableCount {
    addr: u32,
    entries: u32,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HookLists {
    #[serde(default)]
    function: Vec<FunctionHook>,
    #[serde(default)]
    midasm: Vec<MidAsmHook>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FunctionHook {
    addr: u32,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MidAsmHook {
    addr: u32,
    name: String,
    #[serde(default)]
    after: bool,
    action: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Optimizations {
    #[serde(default)]
    locals: bool,
    #[serde(default)]
    trap_as_nop: bool,
    control_flow: Option<String>,
    #[serde(default)]
    dispatch: Vec<u32>,
}

impl Config {
    /// Reads the config at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new(""));
        Self::parse(&text, dir).with_context(|| format!("invalid config {}", path.display()))
    }

    /// Parses the text of a config whose file lies in `dir`, against which its paths are
    /// resolved.
    pub fn parse(text: &str, dir: &Path) -> Result<Self> {
        let file: File = toml::from_str(text)?;
        if file.optimizations.locals {
            bail!("[optimizations] locals is not implemented");
        }
        let control_flow = match file.optimizations.control_flow.as_deref() {
            Some("dispatch") => ControlFlow::Dispatch,
            None | Some("structured") => ControlFlow::Structured,
            Some(other) => bail!(
                "[optimizations] control_flow is \"dispatch\" or \"structured\", not {other:?}"
            ),
        };
        let span = |span: &Span| Function {
            addr: span.addr,
            size: span.size,
        };
        let mut midasm = Vec::new();
        for hook in &file.hooks.midasm {
            let action = Action::parse(hook.action.as_deref().unwrap_or("continue"))
                .map_err(|why| anyhow::anyhow!("hook {}: {why}", hook.name))?;
            midasm.push(MidAsm {
                addr: hook.addr,
                name: hook.name.clone(),
                after: hook.after,
                action,
            });
        }
        let overrides = file
            .hooks
            .function
            .iter()
            .map(|hook| Override {
                addr: hook.addr,
                name: hook.name.clone(),
            })
            .collect();
        Ok(Self {
            xex: dir.join(&file.main.xex),
            out: dir.join(&file.main.out),
            crate_name: file.main.crate_name,
            functions_per_crate: file
                .main
                .functions_per_crate
                .unwrap_or(DEFAULT_FUNCTIONS_PER_CRATE),
            runtime: file.main.runtime.map(|runtime| dir.join(runtime)),
            functions: file.analysis.functions.iter().map(span).collect(),
            skip: file.analysis.skip.iter().map(span).collect(),
            table_entries: file
                .analysis
                .jump_tables
                .iter()
                .map(|table| (table.addr, table.entries))
                .collect(),
            setjmp: file.analysis.setjmp,
            longjmp: file.analysis.longjmp,
            hooks: Hooks { overrides, midasm },
            trap_as_nop: file.optimizations.trap_as_nop,
            control_flow,
            dispatch: file.optimizations.dispatch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[main]
xex = "game/default.xex"
out = "../out"
crate_name = "game-ppc"
"#;

    #[test]
    fn a_minimal_config_takes_the_defaults_and_resolves_its_paths() {
        let config = Config::parse(MINIMAL, Path::new("configs")).unwrap();
        assert_eq!(config.xex, Path::new("configs").join("game/default.xex"));
        assert_eq!(config.out, Path::new("configs").join("../out"));
        assert_eq!(config.crate_name, "game-ppc");
        assert_eq!(config.functions_per_crate, DEFAULT_FUNCTIONS_PER_CRATE);
        assert_eq!(config.runtime, None);
        assert!(config.functions.is_empty() && config.table_entries.is_empty());
        assert_eq!(config.hooks, Hooks::default());
        assert!(!config.trap_as_nop);
        assert_eq!(config.control_flow, ControlFlow::Structured);
    }

    #[test]
    fn every_section_is_read() {
        let text = format!(
            "{MINIMAL}functions_per_crate = 50\nruntime = \"rt\"\n{}",
            r#"
[analysis]
functions = [ { addr = 0x82001000, size = 0x120 } ]
skip = [ { addr = 0x82050000, size = 0x40 } ]
jump_tables = [ { addr = 0x82010000, entries = 12 } ]
setjmp = 0x82020000
longjmp = 0x82020100

[hooks]
function = [ { addr = 0x82001000, name = "my_memcpy" } ]
midasm = [
    { addr = 0x82001008, name = "fix_fov" },
    { addr = 0x8200100C, name = "skip", after = true, action = "jump_if_true:0x82001010" },
]

[optimizations]
trap_as_nop = true
control_flow = "dispatch"
dispatch = [0x82001000, 0x82002000]
"#
        );
        let config = Config::parse(&text, Path::new("")).unwrap();
        assert_eq!(config.functions_per_crate, 50);
        assert_eq!(config.runtime, Some(PathBuf::from("rt")));
        assert_eq!(
            config.functions,
            [Function {
                addr: 0x8200_1000,
                size: 0x120
            }]
        );
        assert_eq!(config.skip[0].addr, 0x8205_0000);
        assert_eq!(config.table_entries, BTreeMap::from([(0x8201_0000, 12)]));
        assert_eq!(config.setjmp, Some(0x8202_0000));
        assert_eq!(config.longjmp, Some(0x8202_0100));
        assert_eq!(config.hooks.overrides[0].name, "my_memcpy");
        assert_eq!(config.hooks.midasm[0].action, Action::Continue);
        assert!(!config.hooks.midasm[0].after);
        assert_eq!(
            config.hooks.midasm[1].action,
            Action::JumpIfTrue(0x8200_1010)
        );
        assert!(config.hooks.midasm[1].after);
        assert!(config.trap_as_nop);
        assert_eq!(config.control_flow, ControlFlow::Dispatch);
        assert_eq!(config.dispatch, [0x8200_1000, 0x8200_2000]);
    }

    #[test]
    fn unknown_keys_locals_and_bad_actions_are_errors() {
        let error = |text: &str| Config::parse(text, Path::new("")).unwrap_err().to_string();
        assert!(error(&format!("{MINIMAL}outt = \"x\"\n")).contains("unknown field"));
        assert!(error(&format!("{MINIMAL}[analysis]\nsetjump = 1\n")).contains("unknown field"));
        assert!(
            error(&format!("{MINIMAL}[optimizations]\nlocals = true\n"))
                .contains("not implemented")
        );
        assert!(
            error(&format!(
                "{MINIMAL}[hooks]\nmidasm = [ {{ addr = 1, name = \"h\", action = \"skip\" }} ]\n"
            ))
            .contains("no hook action")
        );
        assert!(error("[main]\nxex = \"a\"\n").contains("missing field"));
        assert!(
            error(&format!(
                "{MINIMAL}[optimizations]\ncontrol_flow = \"relooper\"\n"
            ))
            .contains("not \"relooper\"")
        );
    }

    #[test]
    fn the_example_config_of_the_docs_is_valid() {
        let text = include_str!("../../../docs/config.example.toml");
        let config = Config::parse(text, Path::new("")).unwrap();
        assert!(!config.hooks.midasm.is_empty(), "the example shows hooks");
        assert!(config.setjmp.is_some() && config.longjmp.is_some());
    }
}
