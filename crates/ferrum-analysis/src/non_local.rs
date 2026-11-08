// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The C runtime's `setjmp` and `longjmp`, recognized by what they do.
//!
//! Generated code has to know the function that returns twice and the one that never returns. A
//! retail executable names neither, but the 64-bit PowerPC ABI fixes what they do: `setjmp` saves
//! into the buffer its first argument points to the state a callee must preserve, and returns 0;
//! `longjmp` loads that state back, so that the caller of `setjmp` sees it return again.
//!
//! - A `setjmp` stores through r3, before its `blr`, the caller's r1 (it builds no frame of its
//!   own), a copy of the link register and every GPR from r14 to r31, and returns with 0 in r3,
//!   set by `li r3,0`. It makes no call and has no branch other than the `blr`, apart from a
//!   conditional branch through CTR, which leaves it early: the C runtime of the Xbox 360 SDK
//!   starts with one, to an address it reads from memory.
//! - A `longjmp` loads r1, r14 to r31 and a value that it moves to the link register, from the
//!   slots where a `setjmp` stored them, through r3 or a copy of it, and returns with `blr`.
//!
//! Matching the slots of `longjmp` to those of a `setjmp` keeps the layout of the buffer out of
//! this code, and tells `longjmp` apart from routines that load a whole context from another
//! structure. Only the targets of calls are candidates. Several may match; the caller decides.

use std::collections::BTreeSet;
use std::ops::Range;

use ferrum_decoder::{Gpr, Insn, decode};

use crate::code::Code;
use crate::flow::{Flow, Target, branch_target, flow, links};
use crate::regs::{Writes, gpr_writes};

#[cfg(test)]
mod tests;

/// The routines that have the shape of `setjmp` and of `longjmp`, by entry address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NonLocalRoutines {
    /// The candidates for `setjmp`.
    pub setjmp: Vec<u32>,
    /// The candidates for `longjmp`.
    pub longjmp: Vec<u32>,
}

/// The most instructions walked from an entry. The routines of the C runtime have under 200.
const MAX_RUN: usize = 1024;

/// The index of the link register in [`Slots`], after the 32 GPRs.
const LR: usize = 32;

/// Where a `setjmp` stores each value, as a displacement from the buffer: index N for rN, and
/// [`LR`] for the link register.
type Slots = [Option<i32>; 33];

/// The values that `setjmp` saves and `longjmp` restores: r1, r14 to r31 and the link register.
fn saved() -> impl Iterator<Item = usize> {
    std::iter::once(1).chain(14..32).chain(std::iter::once(LR))
}

/// Finds the routines with the shape of `setjmp` and `longjmp` among the targets of the calls in
/// `code_ranges` of `code`.
pub fn find_non_local(code: &Code<'_>, code_ranges: &[Range<u32>]) -> NonLocalRoutines {
    let in_code = |addr: u32| code_ranges.iter().any(|range| range.contains(&addr));
    let mut targets = BTreeSet::new();
    for range in code_ranges {
        let mut addr = u64::from(range.start);
        while addr + 4 <= u64::from(range.end) {
            // Inside a range of 32-bit addresses, so it fits.
            let at = addr as u32;
            if let Some(insn) = code.word(at).and_then(decode)
                && links(&insn)
                && let Some(Target::Address(target)) = branch_target(&insn, at)
                && in_code(target)
            {
                targets.insert(target);
            }
            addr += 4;
        }
    }
    let mut found = NonLocalRoutines::default();
    let mut layouts = Vec::new();
    for &entry in &targets {
        if let Some(slots) = setjmp_slots(code, entry) {
            found.setjmp.push(entry);
            layouts.push(slots);
        }
    }
    for &entry in &targets {
        if layouts.iter().any(|slots| restores(code, entry, slots)) {
            found.longjmp.push(entry);
        }
    }
    found
}

/// The registers that `writes` may change, as a mask.
fn mask(writes: Writes) -> u32 {
    match writes {
        Writes::Some(mask) => mask,
        Writes::All => u32::MAX,
    }
}

/// The register and the displacement of a store of a word or a doubleword through `base`.
fn store_through(insn: &Insn, base: u8) -> Option<(u8, i32)> {
    match *insn {
        Insn::Std { rs, ds, ra } if ra == Gpr(base) => Some((rs.0, i32::from(ds))),
        Insn::Stw { rs, d, ra } if ra == Gpr(base) => Some((rs.0, i32::from(d))),
        _ => None,
    }
}

/// The register, the displacement and the base of a load of a word or a doubleword.
fn load(insn: &Insn) -> Option<(u8, i32, u8)> {
    match *insn {
        Insn::Ld { rt, ds, ra } => Some((rt.0, i32::from(ds), ra.0)),
        Insn::Lwz { rt, d, ra } => Some((rt.0, i32::from(d), ra.0)),
        _ => None,
    }
}

/// Returns whether `insn` ends a routine: an unconditional `blr`.
fn is_return(insn: &Insn, addr: u32) -> bool {
    flow(insn, addr)
        == Flow::Jump {
            target: Target::Lr,
            conditional: false,
        }
}

/// The slots of the routine at `entry`, if it is a `setjmp`.
fn setjmp_slots(code: &Code<'_>, entry: u32) -> Option<Slots> {
    let mut slots: Slots = [None; 33];
    // The GPRs that hold the value of the link register.
    let mut link = 0u32;
    // Whether r3 still holds the buffer, and whether it holds the 0 of `li r3,0`.
    let mut buffer = true;
    let mut zero = false;
    let mut addr = entry;
    for _ in 0..MAX_RUN {
        let insn = decode(code.word(addr)?)?;
        if is_return(&insn, addr) {
            let complete = saved().all(|slot| slots[slot].is_some());
            return (complete && zero).then_some(slots);
        }
        match flow(&insn, addr) {
            Flow::Jump {
                target: Target::Ctr,
                conditional: true,
            } => {}
            Flow::Jump { .. } => return None,
            Flow::Next if links(&insn) => return None,
            Flow::Next => {}
        }
        if buffer && let Some((reg, offset)) = store_through(&insn, 3) {
            if reg == 1 || (14..32).contains(&reg) {
                slots[usize::from(reg)] = Some(offset);
            }
            if link & (1 << reg) != 0 {
                slots[LR] = Some(offset);
            }
        }
        let writes = gpr_writes(&insn);
        if writes.contains(1) {
            return None;
        }
        link &= !mask(writes);
        if let Insn::Mfspr { rt, spr: 8 } = insn {
            link |= 1 << rt.0;
        }
        if writes.contains(3) {
            buffer = false;
            zero = matches!(
                insn,
                Insn::Addi {
                    rt: Gpr(3),
                    ra: Gpr(0),
                    si: 0
                }
            );
        }
        addr = addr.checked_add(4)?;
    }
    None
}

/// Returns whether the routine at `entry` is a `longjmp` for the buffer layout `slots`: before
/// its first unconditional `blr`, it loads each saved GPR from its slot and moves the value of
/// the link register's slot to the link register.
///
/// The walk goes through the instructions in address order. A conditional branch goes to a path
/// the walk does not follow. A call is allowed, since the C runtime's `longjmp` makes one before
/// it restores, and it changes the link register but is not taken to change any GPR, although
/// the ABI lets a callee change r3 to r12: that `longjmp` keeps its copy of the buffer in r7
/// across the call, and so relies on its callee, in the same runtime, leaving r7 alone.
fn restores(code: &Code<'_>, entry: u32, slots: &Slots) -> bool {
    // The GPRs that hold the buffer, the GPRs restored from their slots, and the GPRs that hold
    // the value of the link register's slot.
    let mut buffer = 1u32 << 3;
    let mut restored = 0u32;
    let mut link_value = 0u32;
    let mut link_restored = false;
    let mut addr = entry;
    for _ in 0..MAX_RUN {
        let Some(insn) = code.word(addr).and_then(decode) else {
            return false;
        };
        if is_return(&insn, addr) {
            return link_restored
                && saved()
                    .filter(|&slot| slot != LR)
                    .all(|reg| restored & (1 << reg) != 0);
        }
        match flow(&insn, addr) {
            Flow::Jump {
                conditional: true, ..
            } => {}
            Flow::Jump { .. } => return false,
            Flow::Next => {}
        }
        if links(&insn) {
            link_restored = false;
        }
        if let Insn::Mtspr { spr: 8, rs } = insn {
            link_restored = link_value & (1 << rs.0) != 0;
        }
        // What the instruction reads, before what it writes.
        let loaded = load(&insn).filter(|&(_, _, base)| buffer & (1 << base) != 0);
        let copy = match insn {
            Insn::Or {
                ra,
                rs,
                rb,
                rc: false,
            } if rs == rb && buffer & (1 << rs.0) != 0 => Some(ra.0),
            _ => None,
        };
        let written = mask(gpr_writes(&insn));
        buffer &= !written;
        restored &= !written;
        link_value &= !written;
        if let Some(reg) = copy {
            buffer |= 1 << reg;
        }
        if let Some((reg, offset, _)) = loaded {
            if slots[usize::from(reg)] == Some(offset) {
                restored |= 1 << reg;
            }
            if slots[LR] == Some(offset) {
                link_value |= 1 << reg;
            }
        }
        let Some(next) = addr.checked_add(4) else {
            return false;
        };
        addr = next;
    }
    false
}
