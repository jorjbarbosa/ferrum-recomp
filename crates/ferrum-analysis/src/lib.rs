// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Static analysis of guest code, in preparation for code generation.
//!
//! [`discover`] finds the functions of an image from `.pdata`, the entry point and exports, branch
//! targets, pointers in data, a sweep of the gaps and the overrides of the config, and works out
//! which functions never return. [`build`] splits one function into basic blocks by following
//! the code from its entry, resolving the jump tables of its `switch` statements on the way, and
//! [`flow`] says what each instruction does to the flow of control. [`find_save_restore`] finds
//! the compiler's register save and restore routines, which code generation inlines instead of
//! calling, and [`find_non_local`] the C runtime's `setjmp` and `longjmp`.
//!
//! The liveness of CR, XER, CTR and the reservation is not done yet.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(test)]
mod asm;
mod cfg;
mod code;
mod discover;
mod error;
mod flow;
mod jump_table;
mod non_local;
mod regs;
mod save_restore;

pub use cfg::{Block, Cfg, Exit, Function, Rules, build};
pub use code::Code;
pub use discover::{Discovery, Input, Source, THUNK_SIZE, Warning, discover};
pub use error::Error;
pub use flow::{Flow, Target, branch_target, flow, is_unconditional, links};
pub use jump_table::JumpTable;
pub use non_local::{NonLocalRoutines, find_non_local};
pub use save_restore::{Family, Routine, SaveRestore, find_save_restore};
