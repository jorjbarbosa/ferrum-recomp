// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Errors of code generation.

use std::collections::BTreeMap;

/// Why code could not be generated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The function could not be split into blocks.
    #[error(transparent)]
    Analysis(#[from] ferrum_analysis::Error),
    /// Instructions whose opcode has no `emit_*` yet, counted per mnemonic over everything that was
    /// generated. A form with OE=1 counts under the mnemonic with `o` (`addo`).
    #[error("opcodes without emit_*: {}", list(counts))]
    MissingEmit {
        /// How many instructions of each mnemonic.
        counts: BTreeMap<String, usize>,
    },
    /// An `mfspr` or `mtspr` of a register outside the runtime's policy.
    #[error("{op} at {addr:#010x} names SPR {spr}, which generated code does not map")]
    UnmappedSpr {
        /// Address of the instruction.
        addr: u32,
        /// `mfspr` or `mtspr`.
        op: &'static str,
        /// The SPR number.
        spr: u16,
    },
    /// A call or tail call to an address that is neither a function of the list nor a save or
    /// restore routine.
    #[error("branch at {addr:#010x} to {target:#010x}, which is no known function or routine")]
    UnknownTarget {
        /// Address of the branch.
        addr: u32,
        /// Where it goes.
        target: u32,
    },
    /// A tail call to `setjmp`, which would return to a frame whose call site is not a call to
    /// `setjmp`, so that no frame could resume after a `longjmp`.
    #[error("tail call to setjmp at {addr:#010x}, which a longjmp could not come back to")]
    SetjmpTailCall {
        /// Address of the branch.
        addr: u32,
    },
    /// A mid-asm hook that the code cannot honor.
    #[error("hook {name} at {addr:#010x}: {why}")]
    InvalidHook {
        /// The address of its instruction.
        addr: u32,
        /// Its name in the config.
        name: String,
        /// What is wrong with it.
        why: &'static str,
    },
    /// An instruction form that the ISA calls invalid.
    #[error("invalid form of {mnemonic} at {addr:#010x}: {why}")]
    InvalidForm {
        /// Address of the instruction.
        addr: u32,
        /// The instruction.
        mnemonic: &'static str,
        /// What makes it invalid.
        why: &'static str,
    },
    /// An output layout that cannot be written, such as an invalid crate name.
    #[error("invalid output layout: {why}")]
    InvalidLayout {
        /// What is wrong with it.
        why: String,
    },
}

/// `add x2, adde x1`.
fn list(counts: &BTreeMap<String, usize>) -> String {
    let items: Vec<String> = counts
        .iter()
        .map(|(name, count)| format!("{name} x{count}"))
        .collect();
    items.join(", ")
}
