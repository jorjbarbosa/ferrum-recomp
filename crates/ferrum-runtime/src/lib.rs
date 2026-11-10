// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Minimal runtime for recompiled code: guest CPU context, memory, function table, kernel traits.
//!
//! This is the only crate in the workspace allowed to contain `unsafe`, so that generated code can
//! stay entirely safe. Every `unsafe` block carries a `// SAFETY:` comment, which clippy enforces.
//!
//! [`Memory`] is the guest's flat 32-bit address space, read and written in big-endian through a
//! safe API that is sound when guest threads share it. [`PpcContext`] holds the registers of one
//! guest thread, including the reservation of `lwarx`/`stwcx.` and the [`TimeBase`] that `mftb`
//! reads; [`Spr`] says which special-purpose registers generated code may name, [`Fpscr`] holds the
//! floating-point status and [`Vscr`] the vector status. [`FnTable`] maps
//! guest addresses to recompiled functions for indirect calls, and the [`Xboxkrnl`] and [`Xam`]
//! traits are what a port implements for the imports, reached through [`Kernels`]. [`ops`] holds
//! the helpers generated code calls. [`longjmp`], [`Jumps`] and [`enter`] carry the guest's
//! `setjmp` and `longjmp` across recompiled frames by unwinding, and [`HookTable`] holds the port's
//! mid-asm hooks. [`no_block`] is what generated code calls when a jump table sends it to an
//! address where none of the function's blocks starts.

#![warn(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(not(target_pointer_width = "64"))]
compile_error!("ferrum-runtime maps the whole 4 GiB guest address space and needs a 64-bit host");

mod branch;
mod context;
mod error;
mod fn_table;
mod fpscr;
mod hook;
mod jump;
mod kernel;
mod memory;
pub mod ops;
mod registers;
mod spr;
mod time_base;
mod v128;
mod vscr;

#[cfg(test)]
mod test_support;

pub use branch::no_block;
pub use context::{INITIAL_MSR, PpcContext, Reserve, XENON_PVR};
pub use error::Error;
pub use fn_table::{FnTable, GuestFn};
pub use fpscr::Fpscr;
pub use hook::{HookFn, HookTable};
pub use jump::{Jumps, LongJmp, enter, longjmp};
pub use kernel::{Kernels, Unimplemented, Xam, Xboxkrnl};
pub use memory::{GUARD_SIZE, Memory, SLACK};
pub use registers::{Cr, Xer};
pub use spr::Spr;
pub use time_base::{HostTimeBase, TIME_BASE_HZ, TimeBase, host_time_base};
pub use v128::V128;
pub use vscr::Vscr;
