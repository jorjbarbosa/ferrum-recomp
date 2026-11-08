// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The compiler's register save and restore routines.
//!
//! A prologue saves the non-volatile registers from r14 (or f14, v14, v64) up with `bl` into the
//! middle of a chain of stores, `__savegprlr_N` and its kin, and an epilogue restores them with
//! `b __restgprlr_N`. Calling into the middle of a routine has no equivalent in generated code, so
//! code generation inlines the rest of the chain instead.
//!
//! A chain is recognized by its whole shape, never by its first word alone, which normal
//! prologues also contain: consecutive registers to consecutive slots off one base register, up
//! to the `blr`.

use std::collections::BTreeMap;

use ferrum_decoder::{Fpr, Gpr, Insn, Vr, decode};

use crate::code::Code;

#[cfg(test)]
mod tests;

/// Which kind of routine a chain is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// `__savegprlr_N`: `std` of rN to r31, then `stw r12` of the link register, then `blr`.
    SaveGprLr,
    /// `__restgprlr_N`: `ld` of rN to r31, then `lwz r12`, `mtlr r12` and `blr`.
    RestoreGprLr,
    /// `__savefpr_N`: `stfd` of fN to f31, then `blr`.
    SaveFpr,
    /// `__restfpr_N`: `lfd` of fN to f31, then `blr`.
    RestoreFpr,
    /// `__savevmx_N`: pairs of `li` and `stvx` of vN to v31, or of `stvx128` of vN to v127.
    SaveVmx,
    /// `__restvmx_N`: pairs of `li` and `lvx` of vN to v31, or of `lvx128` of vN to v127.
    RestoreVmx,
}

/// One entry point of a save or restore routine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Routine {
    /// The kind of routine.
    pub family: Family,
    /// The first register the entry saves or restores: this is `__savegprlr_<register>` and so
    /// on.
    pub register: u8,
    /// Address of the `blr` that ends the chain.
    pub end: u32,
}

/// Every entry point of every routine found, by address.
pub type SaveRestore = BTreeMap<u32, Routine>;

/// A decoded word and its address.
type Slot = (u32, Option<Insn>);

/// A chain matched at some word: its family, its registers and its layout in words.
struct Chain {
    family: Family,
    first: u8,
    count: usize,
    /// Words from one entry to the next.
    stride: usize,
    /// Words in the whole chain, `blr` included.
    len: usize,
}

type Matcher = fn(&[Slot]) -> Option<Chain>;

const MATCHERS: [Matcher; 8] = [
    save_gpr,
    restore_gpr,
    save_fpr,
    restore_fpr,
    |slots| vmx(slots, Family::SaveVmx, 14, 18),
    |slots| vmx(slots, Family::SaveVmx, 64, 64),
    |slots| vmx(slots, Family::RestoreVmx, 14, 18),
    |slots| vmx(slots, Family::RestoreVmx, 64, 64),
];

/// Finds every save and restore routine in `code`.
pub fn find_save_restore(code: &Code<'_>) -> SaveRestore {
    let slots: Vec<Slot> = code
        .words()
        .map(|(addr, word)| (addr, decode(word)))
        .collect();
    let mut found = SaveRestore::new();
    for start in 0..slots.len() {
        let rest = &slots[start..];
        for chain in MATCHERS.iter().filter_map(|matcher| matcher(rest)) {
            let end = rest[chain.len - 1].0;
            for k in 0..chain.count {
                let routine = Routine {
                    family: chain.family,
                    // At most 64 registers from v64, so this stays below 128.
                    register: chain.first + k as u8,
                    end,
                };
                found.insert(rest[k * chain.stride].0, routine);
            }
        }
    }
    found
}

fn insn(slots: &[Slot], index: usize) -> Option<Insn> {
    slots.get(index)?.1
}

fn is_blr(insn: Option<Insn>) -> bool {
    matches!(
        insn,
        Some(Insn::Bclr {
            bo: 20,
            bh: 0,
            lk: false,
            ..
        })
    )
}

/// What one access of a doubleword chain names: the register, the displacement and the base.
type Access = (u8, i16, Gpr);

/// The base register and the first offset of the 18 consecutive doubleword slots, for registers
/// 14 to 31, that the instructions at the start of `slots` access, if they line up.
fn doublewords(slots: &[Slot], access: impl Fn(Insn) -> Option<Access>) -> Option<(Gpr, i32)> {
    let (_, d0, base) = access(insn(slots, 0)?).filter(|&(reg, _, _)| reg == 14)?;
    let d0 = i32::from(d0);
    for k in 1..18u8 {
        let (reg, d, ra) = access(insn(slots, usize::from(k))?)?;
        if reg != 14 + k || ra != base || i32::from(d) != d0 + 8 * i32::from(k) {
            return None;
        }
    }
    Some((base, d0))
}

/// A chain of one instruction per register, from 14 to 31.
const fn by_register(family: Family, len: usize) -> Chain {
    Chain {
        family,
        first: 14,
        count: 18,
        stride: 1,
        len,
    }
}

fn save_gpr(slots: &[Slot]) -> Option<Chain> {
    let (base, d0) = doublewords(slots, |insn| match insn {
        Insn::Std { rs, ds, ra } => Some((rs.0, ds, ra)),
        _ => None,
    })?;
    let link = matches!(insn(slots, 18)?, Insn::Stw { rs: Gpr(12), d, ra }
        if ra == base && i32::from(d) == d0 + 8 * 18);
    (link && is_blr(insn(slots, 19))).then_some(by_register(Family::SaveGprLr, 20))
}

fn restore_gpr(slots: &[Slot]) -> Option<Chain> {
    let (base, d0) = doublewords(slots, |insn| match insn {
        Insn::Ld { rt, ds, ra } => Some((rt.0, ds, ra)),
        _ => None,
    })?;
    let link = matches!(insn(slots, 18)?, Insn::Lwz { rt: Gpr(12), d, ra }
        if ra == base && i32::from(d) == d0 + 8 * 18);
    let mtlr = matches!(
        insn(slots, 19)?,
        Insn::Mtspr {
            spr: 8,
            rs: Gpr(12)
        }
    );
    (link && mtlr && is_blr(insn(slots, 20))).then_some(by_register(Family::RestoreGprLr, 21))
}

fn save_fpr(slots: &[Slot]) -> Option<Chain> {
    doublewords(slots, |insn| match insn {
        Insn::Stfd {
            frs: Fpr(reg),
            d,
            ra,
        } => Some((reg, d, ra)),
        _ => None,
    })?;
    is_blr(insn(slots, 18)).then_some(by_register(Family::SaveFpr, 19))
}

fn restore_fpr(slots: &[Slot]) -> Option<Chain> {
    doublewords(slots, |insn| match insn {
        Insn::Lfd {
            frt: Fpr(reg),
            d,
            ra,
        } => Some((reg, d, ra)),
        _ => None,
    })?;
    is_blr(insn(slots, 18)).then_some(by_register(Family::RestoreFpr, 19))
}

/// The vector register and the two address registers of `insn`, if it is the access of `family`:
/// `stvx`/`lvx` for v0 to v31, or `stvx128`/`lvx128` when `wide`.
fn vector_access(family: Family, wide: bool, insn: Insn) -> Option<(u8, Gpr, Gpr)> {
    match (family, wide, insn) {
        (Family::SaveVmx, false, Insn::Stvx { vs: Vr(v), ra, rb })
        | (Family::SaveVmx, true, Insn::Stvx128 { vs: Vr(v), ra, rb })
        | (Family::RestoreVmx, false, Insn::Lvx { vd: Vr(v), ra, rb })
        | (Family::RestoreVmx, true, Insn::Lvx128 { vd: Vr(v), ra, rb }) => Some((v, ra, rb)),
        _ => None,
    }
}

/// Pairs of `li rX, offset` and a vector access of `vN, rX, rY`, for `count` registers from
/// `first`, with the offset stepping by 16, then `blr`.
fn vmx(slots: &[Slot], family: Family, first: u8, count: u8) -> Option<Chain> {
    let wide = first >= 32;
    let mut layout: Option<(Gpr, Gpr, i32)> = None;
    for k in 0..count {
        let index = 2 * usize::from(k);
        let Insn::Addi { rt, ra: Gpr(0), si } = insn(slots, index)? else {
            return None;
        };
        let (v, ra, rb) = vector_access(family, wide, insn(slots, index + 1)?)?;
        let offset = i32::from(si) - 16 * i32::from(k);
        let (index_reg, base_reg, offset0) = *layout.get_or_insert((rt, rb, offset));
        if v != first + k || ra != rt || rt != index_reg || rb != base_reg || offset != offset0 {
            return None;
        }
    }
    let len = 2 * usize::from(count) + 1;
    is_blr(insn(slots, len - 1)).then_some(Chain {
        family,
        first,
        count: usize::from(count),
        stride: 2,
        len,
    })
}
