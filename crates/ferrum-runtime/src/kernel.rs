// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The kernel interface: what generated code calls for an import, and what it passes along.
//!
//! A port implements [`Xboxkrnl`] and [`Xam`]. Every method has a default that panics, so a port
//! only writes the imports its game uses. Generated code reaches them through [`Kernels`], which
//! every guest function receives and passes on, so that the kernel can call back into the guest.

use std::fmt;

use crate::fn_table::FnTable;
use crate::hook::HookTable;
use crate::{Memory, PpcContext};

#[cfg(test)]
mod tests;

/// Declares a kernel trait: the methods every library has, then one per exported function.
macro_rules! kernel_trait {
    (
        $(#[$attr:meta])*
        $name:ident, $library:literal { $($ordinal:literal $method:ident,)* }
    ) => {
        $(#[$attr])*
        ///
        /// The traits require `Sync`, because every guest thread calls them. Generated code calls
        /// a method with the guest thread's context, the memory, and the [`Kernels`] it was given,
        /// which lets the method call guest functions in turn.
        #[allow(non_snake_case)]
        pub trait $name: Sync {
            #[doc = concat!("Returns the guest address of the variable that `", $library, "`")]
            /// exports under `name`, for the loader to write into the import slot.
            ///
            /// The default implementation panics with the name.
            fn resolve_variable(&self, name: &str) -> u32 {
                unimplemented_variable($library, name)
            }

            /// Called for an imported function whose ordinal has no name in the ordinal table.
            ///
            /// The default implementation panics with the ordinal and LR.
            fn unnamed_import(
                &self,
                ordinal: u16,
                ctx: &mut PpcContext,
                mem: &Memory,
                k: &Kernels<'_>,
            ) {
                let _ = (mem, k);
                unimplemented_ordinal($library, ordinal, ctx.lr)
            }

            $(
                #[doc = concat!(
                    "The function `", stringify!($method), "`, ordinal ", stringify!($ordinal),
                    " of `", $library, "`."
                )]
                ///
                /// The default implementation panics with the name and LR.
                fn $method(&self, ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {
                    let _ = (mem, k);
                    unimplemented_import(stringify!($method), ctx.lr)
                }
            )*
        }
    };
}

// The two traits, with one method per function export: generated from the ordinal tables of
// ferrum-xex by tests/kernel_exports.rs, which also checks that the file is up to date.
include!("kernel/exports.in");

/// What every guest function receives besides its context and the memory: the kernel and the
/// function table, so that imports and indirect calls can be resolved.
#[derive(Clone, Copy)]
pub struct Kernels<'a> {
    /// The port's implementation of `xboxkrnl.exe`.
    pub krnl: &'a dyn Xboxkrnl,
    /// The port's implementation of `xam.xex`.
    pub xam: &'a dyn Xam,
    /// Every recompiled function, for `bctr`, `bctrl` and kernel callbacks.
    pub table: &'a FnTable,
    /// The mid-asm hooks the port installed; [`HookTable::empty`] for none.
    pub hooks: &'a HookTable,
}

impl fmt::Debug for Kernels<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kernels")
            .field("table", self.table)
            .field("hooks", self.hooks)
            .finish_non_exhaustive()
    }
}

/// A kernel that implements nothing: every import panics. For tests, and as a starting point.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unimplemented;

impl Xboxkrnl for Unimplemented {}

impl Xam for Unimplemented {}

#[cold]
#[inline(never)]
fn unimplemented_import(name: &str, lr: u64) -> ! {
    panic!("unimplemented import: {name} @ LR={lr:#010x}")
}

#[cold]
#[inline(never)]
fn unimplemented_ordinal(library: &str, ordinal: u16, lr: u64) -> ! {
    panic!("unimplemented import: ordinal {ordinal} of {library} @ LR={lr:#010x}")
}

#[cold]
#[inline(never)]
fn unimplemented_variable(library: &str, name: &str) -> ! {
    panic!("unimplemented variable import: {name} of {library}")
}
