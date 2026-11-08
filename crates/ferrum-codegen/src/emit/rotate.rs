// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Rotates and shifts.
//!
//! The mask of a rotate is a constant of the instruction, so it is computed here and emitted as a
//! literal. Word rotates go through `ops::rotl32`, which puts the rotated word in both halves, so
//! that a mask that wraps past bit 32 picks up the high half as the ISA says.

use ferrum_decoder::{Gpr, Insn};

use super::{Emitter, r};
use crate::error::Error;

/// The ISA's MASK(mb, me) over 64 bits, numbered from the most significant: ones from bit `mb` to
/// bit `me`, wrapping around when `mb > me`.
pub(crate) fn mask64(mb: u32, me: u32) -> u64 {
    debug_assert!(mb < 64 && me < 64);
    let from_mb = u64::MAX >> mb;
    let to_me = u64::MAX << (63 - me);
    if mb <= me {
        from_mb & to_me
    } else {
        from_mb | to_me
    }
}

/// The mask of a word rotate: MASK(mb + 32, me + 32).
pub(crate) fn mask32(mb: u8, me: u8) -> u64 {
    mask64(u32::from(mb) + 32, u32::from(me) + 32)
}

/// Emits `insn` if it belongs to this family, and returns whether it did.
pub(super) fn emit(e: &mut Emitter<'_>, insn: &Insn) -> Result<bool, Error> {
    let (ra, value, rc) = match *insn {
        Insn::Rlwinm {
            ra,
            rs,
            sh,
            mb,
            me,
            rc,
        } => (
            ra,
            format!("ops::rotl32({}, {sh}) & {:#x}", r(rs), mask32(mb, me)),
            rc,
        ),
        Insn::Rlwnm {
            ra,
            rs,
            rb,
            mb,
            me,
            rc,
        } => (
            ra,
            format!(
                "ops::rotl32({}, ({} & 0x1f) as u32) & {:#x}",
                r(rs),
                r(rb),
                mask32(mb, me)
            ),
            rc,
        ),
        Insn::Rlwimi {
            ra,
            rs,
            sh,
            mb,
            me,
            rc,
        } => {
            let m = mask32(mb, me);
            let rotated = format!("ops::rotl32({}, {sh})", r(rs));
            (ra, insert(&rotated, &r(ra), m), rc)
        }
        Insn::Rldicl { ra, rs, sh, mb, rc } => (ra, rotate64(rs, sh, mask64(mb.into(), 63)), rc),
        Insn::Rldicr { ra, rs, sh, me, rc } => (ra, rotate64(rs, sh, mask64(0, me.into())), rc),
        Insn::Rldic { ra, rs, sh, mb, rc } => (
            ra,
            rotate64(rs, sh, mask64(mb.into(), 63 - u32::from(sh))),
            rc,
        ),
        Insn::Rldimi { ra, rs, sh, mb, rc } => {
            let m = mask64(mb.into(), 63 - u32::from(sh));
            let rotated = format!("{}.rotate_left({sh})", r(rs));
            (ra, insert(&rotated, &r(ra), m), rc)
        }
        Insn::Rldcl { ra, rs, rb, mb, rc } => (
            ra,
            format!(
                "{}.rotate_left(({} & 0x3f) as u32) & {:#x}",
                r(rs),
                r(rb),
                mask64(mb.into(), 63)
            ),
            rc,
        ),
        Insn::Rldcr { ra, rs, rb, me, rc } => (
            ra,
            format!(
                "{}.rotate_left(({} & 0x3f) as u32) & {:#x}",
                r(rs),
                r(rb),
                mask64(0, me.into())
            ),
            rc,
        ),
        _ => return Ok(shift(e, insn)),
    };
    e.set_rc(ra, value, rc);
    Ok(true)
}

/// `rS` rotated left by the constant `sh`, under `mask`.
fn rotate64(rs: Gpr, sh: u8, mask: u64) -> String {
    format!("{}.rotate_left({sh}) & {mask:#x}", r(rs))
}

/// The bits of `rotated` under `mask`, and those of `old` elsewhere.
fn insert(rotated: &str, old: &str, mask: u64) -> String {
    format!("({rotated} & {mask:#x}) | ({old} & {:#x})", !mask)
}

/// Shifts. A word shift by a register uses 6 bits of it and a doubleword shift 7, so amounts past
/// the width give zero, or the sign for the algebraic shifts. Those set CA when the result is
/// negative and any 1 bit was shifted out.
fn shift(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (ra, rc) = match *insn {
        Insn::Slw { ra, rs, rb, rc } => {
            e.open("{");
            e.line(format!("let n = {} & 0x3f;", r(rb)));
            e.set(
                ra,
                format!(
                    "if n < 32 {{ u64::from(({} as u32) << n) }} else {{ 0 }}",
                    r(rs)
                ),
            );
            (ra, rc)
        }
        Insn::Srw { ra, rs, rb, rc } => {
            e.open("{");
            e.line(format!("let n = {} & 0x3f;", r(rb)));
            e.set(
                ra,
                format!(
                    "if n < 32 {{ u64::from(({} as u32) >> n) }} else {{ 0 }}",
                    r(rs)
                ),
            );
            (ra, rc)
        }
        Insn::Sld { ra, rs, rb, rc } => {
            e.open("{");
            e.line(format!("let n = {} & 0x7f;", r(rb)));
            e.set(ra, format!("if n < 64 {{ {} << n }} else {{ 0 }}", r(rs)));
            (ra, rc)
        }
        Insn::Srd { ra, rs, rb, rc } => {
            e.open("{");
            e.line(format!("let n = {} & 0x7f;", r(rb)));
            e.set(ra, format!("if n < 64 {{ {} >> n }} else {{ 0 }}", r(rs)));
            (ra, rc)
        }
        Insn::Sraw { ra, rs, rb, rc } => {
            e.open("{");
            e.line(format!("let s = {} as i32;", r(rs)));
            e.line(format!("let n = ({} & 0x3f) as u32;", r(rb)));
            e.line("let (v, ca) = if n < 32 { (s >> n, s < 0 && (s as u32) & ((1 << n) - 1) != 0) } else { (s >> 31, s < 0) };");
            e.set(ra, "v as i64 as u64");
            e.line("ctx.xer.ca = ca;");
            (ra, rc)
        }
        Insn::Srawi { ra, rs, sh, rc } => {
            e.open("{");
            e.line(format!("let s = {} as i32;", r(rs)));
            e.set(ra, format!("(s >> {sh}) as i64 as u64"));
            let lost = (1u32 << sh) - 1;
            e.line(format!(
                "ctx.xer.ca = s < 0 && (s as u32) & {lost:#x} != 0;"
            ));
            (ra, rc)
        }
        Insn::Srad { ra, rs, rb, rc } => {
            e.open("{");
            e.line(format!("let s = {} as i64;", r(rs)));
            e.line(format!("let n = ({} & 0x7f) as u32;", r(rb)));
            e.line("let (v, ca) = if n < 64 { (s >> n, s < 0 && (s as u64) & ((1 << n) - 1) != 0) } else { (s >> 63, s < 0) };");
            e.set(ra, "v as u64");
            e.line("ctx.xer.ca = ca;");
            (ra, rc)
        }
        Insn::Sradi { ra, rs, sh, rc } => {
            e.open("{");
            e.line(format!("let s = {} as i64;", r(rs)));
            e.set(ra, format!("(s >> {sh}) as u64"));
            let lost = (1u64 << sh) - 1;
            e.line(format!(
                "ctx.xer.ca = s < 0 && (s as u64) & {lost:#x} != 0;"
            ));
            (ra, rc)
        }
        _ => return false,
    };
    if rc {
        e.record(ra);
    }
    e.close("}");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_count_bits_from_the_top_and_wrap() {
        assert_eq!(mask64(0, 63), u64::MAX);
        assert_eq!(mask64(32, 63), 0xFFFF_FFFF);
        assert_eq!(mask64(0, 0), 0x8000_0000_0000_0000);
        assert_eq!(mask64(63, 63), 1);
        assert_eq!(mask64(63, 0), 0x8000_0000_0000_0001);
        assert_eq!(mask64(4, 59), 0x0FFF_FFFF_FFFF_FFF0);
        assert_eq!(mask64(60, 3), 0xF000_0000_0000_000F);
        // rlwinm masks: 0..31 is the low word, and a wrap takes the high word too.
        assert_eq!(mask32(0, 31), 0xFFFF_FFFF);
        assert_eq!(mask32(16, 31), 0xFFFF);
        assert_eq!(mask32(0, 15), 0xFFFF_0000);
        assert_eq!(mask32(31, 0), 0xFFFF_FFFF_8000_0001);
        assert_eq!(mask32(1, 0), u64::MAX);
    }
}
