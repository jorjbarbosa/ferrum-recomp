// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The table that maps guest addresses to recompiled functions, for indirect calls.

use std::borrow::Cow;
use std::fmt;

use crate::error::Error;
use crate::kernel::Kernels;
use crate::{Memory, PpcContext};

#[cfg(test)]
mod tests;

/// A recompiled guest function. Every generated function has this signature.
pub type GuestFn = fn(&mut PpcContext, &Memory, &Kernels<'_>);

/// Maps the address of every recompiled function to the function, for `bctr`, `bctrl` and the
/// kernel's callbacks.
///
/// Each module registers one dense range: entry `i` is the function at `base + 4 * i`, or `None`
/// where no function starts. Ranges cannot overlap. A lookup checks each range in turn, which is
/// cheap for the few modules a game has.
#[derive(Default)]
pub struct FnTable {
    ranges: Vec<Range>,
}

/// One module's functions: entry `i` starts at `base + 4 * i`.
#[derive(Clone)]
struct Range {
    base: u32,
    functions: Cow<'static, [Option<GuestFn>]>,
}

impl Range {
    /// One past the last address the range covers.
    fn end(&self) -> u64 {
        u64::from(self.base) + 4 * self.functions.len() as u64
    }

    /// Returns the entry for `addr`, or `None` if the range does not cover it.
    fn entry(&self, addr: u32) -> Option<Option<GuestFn>> {
        let offset = addr.wrapping_sub(self.base);
        if !offset.is_multiple_of(4) {
            return None;
        }
        self.functions.get((offset / 4) as usize).copied()
    }
}

impl FnTable {
    /// Returns an empty table.
    pub const fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Registers the functions of one module: `functions[i]` starts at `base + 4 * i`.
    ///
    /// Fails if `base` is not 4-aligned, if the range runs past the end of the address space, or
    /// if it overlaps a range registered before.
    pub fn register(
        &mut self,
        base: u32,
        functions: &'static [Option<GuestFn>],
    ) -> Result<(), Error> {
        self.check_range(base, functions.len())?;
        self.ranges.push(Range {
            base,
            functions: Cow::Borrowed(functions),
        });
        Ok(())
    }

    /// Registers the functions of one module from lists of entries, where `(addr, function)` says
    /// that `function` starts at `addr`. The range covers `words` words from `base`, as with
    /// [`FnTable::register`], and the table owns it.
    ///
    /// A generated root crate registers its functions this way: each crate of the output lists its
    /// own, because a dense array literal over the whole code is slow to compile.
    ///
    /// Fails as [`FnTable::register`] does, and if an entry is not 4-aligned, lies outside the
    /// range or repeats an address.
    pub fn register_entries(
        &mut self,
        base: u32,
        words: usize,
        lists: &[&[(u32, GuestFn)]],
    ) -> Result<(), Error> {
        self.check_range(base, words)?;
        let mut functions: Vec<Option<GuestFn>> = vec![None; words];
        for &(addr, function) in lists.iter().flat_map(|list| list.iter()) {
            let offset = addr.wrapping_sub(base);
            let why = if offset.is_multiple_of(4) {
                match functions.get_mut((offset / 4) as usize) {
                    None => "lies outside its range",
                    Some(Some(_)) => "repeats an address",
                    Some(slot) => {
                        *slot = Some(function);
                        continue;
                    }
                }
            } else {
                "is not 4-aligned"
            };
            return Err(Error::InvalidEntry { addr, why });
        }
        self.ranges.push(Range {
            base,
            functions: Cow::Owned(functions),
        });
        Ok(())
    }

    /// Checks a range of `len` entries from `base` against the rules of [`FnTable::register`].
    fn check_range(&self, base: u32, len: usize) -> Result<(), Error> {
        if !base.is_multiple_of(4) {
            return Err(Error::MisalignedRange { base });
        }
        let start = u64::from(base);
        // `usize` is at most 64 bits wide on every supported host.
        let end = start.saturating_add((len as u64).saturating_mul(4));
        if end > 1 << 32 {
            return Err(Error::RangeOverflow { base, len });
        }
        if let Some(other) = self
            .ranges
            .iter()
            .find(|other| start < other.end() && u64::from(other.base) < end)
        {
            return Err(Error::OverlappingRange {
                base,
                end,
                other: other.base,
            });
        }
        Ok(())
    }

    /// Puts `function` at `addr`, inside a registered range, replacing what was there: how a
    /// port installs the override of a function.
    pub fn set(&mut self, addr: u32, function: GuestFn) -> Result<(), Error> {
        if !addr.is_multiple_of(4) {
            return Err(Error::InvalidEntry {
                addr,
                why: "is not 4-aligned",
            });
        }
        let range = self
            .ranges
            .iter_mut()
            .find(|range| range.entry(addr).is_some())
            .ok_or(Error::InvalidEntry {
                addr,
                why: "lies in no registered range",
            })?;
        let index = (addr.wrapping_sub(range.base) / 4) as usize;
        range.functions.to_mut()[index] = Some(function);
        Ok(())
    }

    /// Returns the function that starts at `addr`, if one is registered.
    pub fn get(&self, addr: u32) -> Option<GuestFn> {
        self.ranges
            .iter()
            .find_map(|range| range.entry(addr))
            .flatten()
    }

    /// Returns the function that starts at `addr`, for an indirect call made with the link
    /// register `lr`. Panics, naming both, if there is none.
    #[inline]
    pub fn lookup(&self, addr: u32, lr: u64) -> GuestFn {
        match self.get(addr) {
            Some(function) => function,
            None => missing_function(addr, lr),
        }
    }
}

impl fmt::Debug for FnTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for range in &self.ranges {
            list.entry(&format_args!("{:#010x}..{:#x}", range.base, range.end()));
        }
        list.finish()
    }
}

#[cold]
#[inline(never)]
fn missing_function(addr: u32, lr: u64) -> ! {
    panic!("no guest function at {addr:#010x} (LR={lr:#010x})")
}
