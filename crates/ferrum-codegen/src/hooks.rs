// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Hooks: functions the port overrides, and mid-asm hooks at given instructions.

use std::fmt::Write as _;

/// What generated code does after a mid-asm hook returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Goes on with the instruction.
    Continue,
    /// Returns from the guest function.
    Return,
    /// Goes to an address of the same function.
    Jump(u32),
    /// Returns from the guest function if the hook returned true.
    ReturnIfTrue,
    /// Goes to an address of the same function if the hook returned true.
    JumpIfTrue(u32),
}

impl Action {
    /// Parses an action as the config writes it: `continue`, `return`, `jump:0x...`,
    /// `return_if_true` or `jump_if_true:0x...`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let address = |hex: &str| {
            let digits = hex.strip_prefix("0x").unwrap_or(hex);
            u32::from_str_radix(digits, 16).map_err(|e| format!("{text:?}: {e}"))
        };
        match text {
            "continue" => Ok(Action::Continue),
            "return" => Ok(Action::Return),
            "return_if_true" => Ok(Action::ReturnIfTrue),
            _ => {
                if let Some(to) = text.strip_prefix("jump_if_true:") {
                    Ok(Action::JumpIfTrue(address(to)?))
                } else if let Some(to) = text.strip_prefix("jump:") {
                    Ok(Action::Jump(address(to)?))
                } else {
                    Err(format!("{text:?} is no hook action"))
                }
            }
        }
    }

    /// The address the action may go to.
    pub(crate) fn target(self) -> Option<u32> {
        match self {
            Action::Jump(to) | Action::JumpIfTrue(to) => Some(to),
            _ => None,
        }
    }
}

/// A function the port replaces with its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    /// The entry of the guest function.
    pub addr: u32,
    /// The name the config gives the hook.
    pub name: String,
}

/// A call to the port at an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MidAsm {
    /// The address of the instruction.
    pub addr: u32,
    /// The name the config gives the hook.
    pub name: String,
    /// Whether the call comes after the instruction rather than before it.
    pub after: bool,
    /// What happens when the hook returns.
    pub action: Action,
}

impl MidAsm {
    /// The expression that calls the hook, which returns whether a conditional action acts.
    pub(crate) fn call(&self) -> String {
        format!(
            "k.hooks.call({:#010x}, {:?}, ctx, mem, k)",
            self.addr, self.name
        )
    }

    /// The statements that call the hook and act on what it returns. For the jump actions, `goto`
    /// gives the statements that go to the address of the function.
    pub(crate) fn statements(&self, goto: impl FnOnce(u32) -> Vec<String>) -> Vec<String> {
        let call = self.call();
        match self.action {
            Action::Continue => vec![format!("{call};")],
            Action::Return => vec![format!("{call};"), "return;".to_owned()],
            Action::Jump(to) => {
                let mut statements = vec![format!("{call};")];
                statements.extend(goto(to));
                statements
            }
            Action::ReturnIfTrue => vec![format!("if {call} {{ return; }}")],
            Action::JumpIfTrue(to) => {
                vec![format!("if {call} {{ {} }}", goto(to).join(" "))]
            }
        }
    }
}

/// The hooks of the config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hooks {
    /// The functions the port replaces.
    pub overrides: Vec<Override>,
    /// The calls to the port at instructions.
    pub midasm: Vec<MidAsm>,
}

/// The text of the root crate's `hooks.rs`.
pub(crate) fn hooks_file(hooks: &Hooks) -> String {
    let mut text = String::from(
        "//! The hooks of the config, by address and name, and a check that the port installed\n\
         //! them: overrides with `FnTable::set`, mid-asm hooks in a `HookTable`.\n\n\
         use ferrum_runtime::{FnTable, HookTable};\n\n",
    );
    let list = |text: &mut String, doc: &str, name: &str, items: Vec<(u32, &str)>| {
        let _ = writeln!(text, "/// {doc}");
        let _ = writeln!(text, "pub const {name}: [(u32, &str); {}] = [", items.len());
        for (addr, hook) in items {
            let _ = writeln!(text, "    ({addr:#010x}, {hook:?}),");
        }
        text.push_str("];\n\n");
    };
    list(
        &mut text,
        "The functions the port overrides, by entry.",
        "OVERRIDES",
        hooks
            .overrides
            .iter()
            .map(|o| (o.addr, o.name.as_str()))
            .collect(),
    );
    list(
        &mut text,
        "The mid-asm hooks, by the address of their instruction.",
        "MIDASM",
        hooks
            .midasm
            .iter()
            .map(|m| (m.addr, m.name.as_str()))
            .collect(),
    );
    text.push_str(
        "/// The names of the hooks the port has not installed, for it to check before running\n\
         /// guest code.\n\
         pub fn missing(table: &FnTable, hooks: &HookTable) -> Vec<&'static str> {\n    \
         let overrides = OVERRIDES.into_iter().filter(|&(addr, _)| table.get(addr).is_none());\n    \
         let midasm = MIDASM.into_iter().filter(|&(addr, _)| hooks.get(addr).is_none());\n    \
         overrides.chain(midasm).map(|(_, name)| name).collect()\n}\n",
    );
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_parse_as_the_config_writes_them() {
        assert_eq!(Action::parse("continue"), Ok(Action::Continue));
        assert_eq!(Action::parse("return"), Ok(Action::Return));
        assert_eq!(Action::parse("return_if_true"), Ok(Action::ReturnIfTrue));
        assert_eq!(
            Action::parse("jump:0x8200100C"),
            Ok(Action::Jump(0x8200_100C))
        );
        assert_eq!(
            Action::parse("jump_if_true:82001010"),
            Ok(Action::JumpIfTrue(0x8200_1010))
        );
        assert!(Action::parse("jump:").is_err());
        assert!(Action::parse("skip").is_err());
    }

    #[test]
    fn each_action_acts_on_the_hook() {
        let hook = |action| MidAsm {
            addr: 0x8200_1008,
            name: "fix_fov".to_owned(),
            after: false,
            action,
        };
        let call = "k.hooks.call(0x82001008, \"fix_fov\", ctx, mem, k)";
        // The statements of a jump come from the caller; these are the dispatcher's.
        let goto = |to: u32| vec![format!("pc = {to:#010x};"), "continue;".to_owned()];
        assert_eq!(
            hook(Action::Continue).statements(goto),
            [format!("{call};")]
        );
        assert_eq!(
            hook(Action::Return).statements(goto),
            [format!("{call};"), "return;".to_owned()]
        );
        assert_eq!(
            hook(Action::Jump(0x8200_100C)).statements(goto),
            [
                format!("{call};"),
                "pc = 0x8200100c;".to_owned(),
                "continue;".to_owned()
            ]
        );
        assert_eq!(
            hook(Action::ReturnIfTrue).statements(goto),
            [format!("if {call} {{ return; }}")]
        );
        assert_eq!(
            hook(Action::JumpIfTrue(0x8200_1010)).statements(goto),
            [format!("if {call} {{ pc = 0x82001010; continue; }}")]
        );
    }

    #[test]
    fn hooks_rs_lists_the_hooks_and_checks_them() {
        let hooks = Hooks {
            overrides: vec![Override {
                addr: 0x8200_1000,
                name: "my_memcpy".to_owned(),
            }],
            midasm: vec![MidAsm {
                addr: 0x8200_1008,
                name: "fix_fov".to_owned(),
                after: false,
                action: Action::Continue,
            }],
        };
        let text = hooks_file(&hooks);
        assert!(
            text.contains(
                "pub const OVERRIDES: [(u32, &str); 1] = [\n    (0x82001000, \"my_memcpy\"),\n];"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "pub const MIDASM: [(u32, &str); 1] = [\n    (0x82001008, \"fix_fov\"),\n];"
            ),
            "{text}"
        );
        assert!(
            text.contains("pub fn missing(table: &FnTable, hooks: &HookTable)"),
            "{text}"
        );
        let empty = hooks_file(&Hooks::default());
        assert!(
            empty.contains("pub const OVERRIDES: [(u32, &str); 0] = [\n];"),
            "{empty}"
        );
    }
}
