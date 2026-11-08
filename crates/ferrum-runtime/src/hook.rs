// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Mid-asm hooks: functions of the port that generated code calls at given instructions.
//!
//! The port's code builds after the generated workspace, so generated code cannot name it. The
//! port puts its hooks in a [`HookTable`] by the address of their instruction, and generated code
//! finds them through [`Kernels::hooks`](crate::Kernels).

use std::collections::BTreeMap;
use std::fmt;

use crate::{Kernels, Memory, PpcContext};

/// A mid-asm hook. What it returns matters only to the actions that test it, `return_if_true` and
/// `jump_if_true`.
pub type HookFn = fn(&mut PpcContext, &Memory, &Kernels<'_>) -> bool;

/// The mid-asm hooks a port installed, by the address of the instruction they belong to.
#[derive(Clone, Default)]
pub struct HookTable {
    hooks: BTreeMap<u32, HookFn>,
}

impl HookTable {
    /// Returns a table with no hook.
    pub const fn new() -> Self {
        Self {
            hooks: BTreeMap::new(),
        }
    }

    /// Returns a shared table with no hook, for a port that installs none.
    pub fn empty() -> &'static HookTable {
        static EMPTY: HookTable = HookTable::new();
        &EMPTY
    }

    /// Installs `hook` at the instruction at `addr`, replacing any hook there.
    pub fn set(&mut self, addr: u32, hook: HookFn) {
        self.hooks.insert(addr, hook);
    }

    /// Returns the hook at the instruction at `addr`, if one is installed.
    pub fn get(&self, addr: u32) -> Option<HookFn> {
        self.hooks.get(&addr).copied()
    }

    /// Calls the hook at `addr`, which the config names `name`, and returns what it returns.
    /// Panics, naming both, if the port did not install it.
    #[inline]
    pub fn call(
        &self,
        addr: u32,
        name: &str,
        ctx: &mut PpcContext,
        mem: &Memory,
        k: &Kernels<'_>,
    ) -> bool {
        match self.get(addr) {
            Some(hook) => hook(ctx, mem, k),
            None => missing_hook(name, addr),
        }
    }
}

impl fmt::Debug for HookTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for addr in self.hooks.keys() {
            list.entry(&format_args!("{addr:#010x}"));
        }
        list.finish()
    }
}

#[cold]
#[inline(never)]
fn missing_hook(name: &str, addr: u32) -> ! {
    panic!("the hook {name} at {addr:#010x} is not installed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::memory;
    use crate::{FnTable, Unimplemented};

    fn sets_r3(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) -> bool {
        ctx.r[3] = 9;
        true
    }

    fn says_no(_: &mut PpcContext, _: &Memory, _: &Kernels<'_>) -> bool {
        false
    }

    #[test]
    fn a_hook_runs_by_its_address_and_a_missing_one_panics() {
        let mut hooks = HookTable::new();
        hooks.set(0x8200_0010, sets_r3);
        hooks.set(0x8200_0020, says_no);
        let table = FnTable::new();
        let k = Kernels {
            krnl: &Unimplemented,
            xam: &Unimplemented,
            table: &table,
            hooks: HookTable::empty(),
        };
        let mut ctx = PpcContext::new();
        assert!(hooks.call(0x8200_0010, "sets_r3", &mut ctx, memory(), &k));
        assert_eq!(ctx.r[3], 9);
        assert!(!hooks.call(0x8200_0020, "says_no", &mut ctx, memory(), &k));
        hooks.set(0x8200_0020, sets_r3);
        assert!(hooks.call(0x8200_0020, "replaced", &mut ctx, memory(), &k));
        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hooks.call(0x8200_0030, "fix_fov", &mut ctx, memory(), &k)
        }))
        .unwrap_err();
        let message = payload.downcast::<String>().unwrap();
        assert_eq!(*message, "the hook fix_fov at 0x82000030 is not installed");
        assert!(HookTable::empty().get(0x8200_0010).is_none());
    }
}
