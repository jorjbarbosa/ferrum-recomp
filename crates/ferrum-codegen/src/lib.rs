// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Rust code generation: turns guest functions into Rust source text.
//!
//! [`Program`] holds the guest code, the functions in it and its save and restore routines, and
//! generates one Rust function per guest function, named by [`function_name`], from the basic
//! blocks of `ferrum-analysis`. [`ControlFlow`] says how the function follows the guest's
//! branches: a `loop { match pc { ... } }` with one arm per block, or structured code, with
//! labeled blocks, loops, `break`, `continue` and `if`, from the function's structured form. Each
//! instruction becomes a few statements over the context, the memory and the helpers of
//! `ferrum-runtime`; [`PRELUDE`] has the `use` lines they need. The generated code contains no
//! `unsafe`.
//!
//! The conventions of generated code: LR is written before a call, branches out of a function
//! are tail calls, calls into save and restore routines are inlined, and arithmetic follows 32-bit
//! mode. Opcodes without an `emit_*` are not fatal one by one: [`Error::MissingEmit`] counts all
//! of them.
//!
//! [`Program::workspace`] lays the functions out as the output workspace, a set of crates that
//! check in parallel, plus a root crate that registers them in the function table; calls between
//! those crates go through the table. [`write_workspace`] writes it. [`NonLocal`] names the guest's
//! `setjmp` and `longjmp`, which generated code carries across frames by unwinding.
//! [`Program::with_imports`] turns calls to import thunks into kernel calls, and
//! [`Program::with_hooks`] wires the functions a port overrides and its mid-asm hooks.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod emit;
mod error;
mod hooks;
mod imports;
mod program;
mod sites;
mod structured;
mod workspace;

#[cfg(test)]
mod tests;

pub use error::Error;
pub use hooks::{Action, Hooks, MidAsm, Override};
pub use imports::{Import, Library, thunk_name};
pub use program::{ControlFlow, NonLocal, PRELUDE, Program, Statistics, function_name};
pub use workspace::{DEFAULT_FUNCTIONS_PER_CRATE, Layout, OutputFile, PROFILE, write_workspace};
