// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Floating-point moves, arithmetic, conversions, compares and the FPSCR instructions.
//!
//! Each instruction is one call of a helper of the runtime's `ops`, which applies the NaN rule of
//! the ISA, or of `ctx.fpscr`. The operands are passed in the order of the instruction's
//! description: `fmadd frT, frA, frC, frB` is `ops::fmadd(&mut ctx.fpscr, a, c, b)`. A record form
//! (Rc=1) then copies FPSCR bits 0:3 into CR1. The loads and stores are in the memory family.

use ferrum_decoder::{Fpr, Insn};

use super::Emitter;
use crate::error::Error;

/// Emits `insn` if it belongs to this family, and returns whether it did.
pub(super) fn emit(e: &mut Emitter<'_>, at: u32, insn: &Insn) -> Result<bool, Error> {
    match *insn {
        Insn::Fmr { frt, frb, rc } => e.set_f(frt, f(frb), rc),
        Insn::Fneg { frt, frb, rc } => e.set_f(frt, format!("ops::fneg({})", f(frb)), rc),
        Insn::Fabs { frt, frb, rc } => e.set_f(frt, format!("ops::fabs({})", f(frb)), rc),
        Insn::Fnabs { frt, frb, rc } => e.set_f(frt, format!("ops::fnabs({})", f(frb)), rc),
        Insn::Fsel {
            frt,
            fra,
            frc,
            frb,
            rc,
        } => {
            let value = format!("ops::fsel({}, {}, {})", f(fra), f(frc), f(frb));
            e.set_f(frt, value, rc);
        }
        Insn::Fcfid { frt, frb, rc } => e.set_f(frt, format!("ops::fcfid({})", f(frb)), rc),
        _ => {
            return Ok(arithmetic(e, insn)
                || multiply_add(e, insn)
                || unary(e, insn)
                || status(e, at, insn)?);
        }
    }
    Ok(true)
}

/// FPR `n`.
fn f(n: Fpr) -> String {
    format!("ctx.f[{}]", n.0)
}

/// `frT = ops::<name>(&mut ctx.fpscr, operands...)`, then CR1 if `rc`.
fn call(e: &mut Emitter<'_>, name: &str, frt: Fpr, operands: &[Fpr], rc: bool) {
    let operands: Vec<String> = operands.iter().map(|&n| f(n)).collect();
    let value = format!("ops::{name}(&mut ctx.fpscr, {})", operands.join(", "));
    e.set_f(frt, value, rc);
}

/// The two-operand arithmetic instructions: add, subtract, multiply and divide.
fn arithmetic(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, frt, a, b, rc) = match *insn {
        Insn::Fadd { frt, fra, frb, rc } => ("fadd", frt, fra, frb, rc),
        Insn::Fadds { frt, fra, frb, rc } => ("fadds", frt, fra, frb, rc),
        Insn::Fsub { frt, fra, frb, rc } => ("fsub", frt, fra, frb, rc),
        Insn::Fsubs { frt, fra, frb, rc } => ("fsubs", frt, fra, frb, rc),
        Insn::Fmul { frt, fra, frc, rc } => ("fmul", frt, fra, frc, rc),
        Insn::Fmuls { frt, fra, frc, rc } => ("fmuls", frt, fra, frc, rc),
        Insn::Fdiv { frt, fra, frb, rc } => ("fdiv", frt, fra, frb, rc),
        Insn::Fdivs { frt, fra, frb, rc } => ("fdivs", frt, fra, frb, rc),
        _ => return false,
    };
    call(e, name, frt, &[a, b], rc);
    true
}

/// The multiply-add instructions: `frA × frC ± frB`, negated or not.
fn multiply_add(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, frt, a, c, b, rc) = match *insn {
        Insn::Fmadd {
            frt,
            fra,
            frc,
            frb,
            rc,
        } => ("fmadd", frt, fra, frc, frb, rc),
        Insn::Fmadds {
            frt,
            fra,
            frc,
            frb,
            rc,
        } => ("fmadds", frt, fra, frc, frb, rc),
        Insn::Fmsub {
            frt,
            fra,
            frc,
            frb,
            rc,
        } => ("fmsub", frt, fra, frc, frb, rc),
        Insn::Fmsubs {
            frt,
            fra,
            frc,
            frb,
            rc,
        } => ("fmsubs", frt, fra, frc, frb, rc),
        Insn::Fnmadd {
            frt,
            fra,
            frc,
            frb,
            rc,
        } => ("fnmadd", frt, fra, frc, frb, rc),
        Insn::Fnmadds {
            frt,
            fra,
            frc,
            frb,
            rc,
        } => ("fnmadds", frt, fra, frc, frb, rc),
        Insn::Fnmsub {
            frt,
            fra,
            frc,
            frb,
            rc,
        } => ("fnmsub", frt, fra, frc, frb, rc),
        Insn::Fnmsubs {
            frt,
            fra,
            frc,
            frb,
            rc,
        } => ("fnmsubs", frt, fra, frc, frb, rc),
        _ => return false,
    };
    call(e, name, frt, &[a, c, b], rc);
    true
}

/// The instructions of one operand, frB: square root, estimates, rounding and conversions.
fn unary(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, frt, b, rc) = match *insn {
        Insn::Fsqrt { frt, frb, rc } => ("fsqrt", frt, frb, rc),
        Insn::Fsqrts { frt, frb, rc } => ("fsqrts", frt, frb, rc),
        Insn::Fres { frt, frb, rc } => ("fres", frt, frb, rc),
        Insn::Frsqrte { frt, frb, rc } => ("frsqrte", frt, frb, rc),
        Insn::Frsp { frt, frb, rc } => ("frsp", frt, frb, rc),
        Insn::Fctiw { frt, frb, rc } => ("fctiw", frt, frb, rc),
        Insn::Fctiwz { frt, frb, rc } => ("fctiwz", frt, frb, rc),
        Insn::Fctid { frt, frb, rc } => ("fctid", frt, frb, rc),
        Insn::Fctidz { frt, frb, rc } => ("fctidz", frt, frb, rc),
        _ => return false,
    };
    call(e, name, frt, &[b], rc);
    true
}

/// The compares and the FPSCR instructions, through `ctx.fpscr`.
fn status(e: &mut Emitter<'_>, at: u32, insn: &Insn) -> Result<bool, Error> {
    match *insn {
        Insn::Fcmpu { bf, fra, frb } => e.line(format!(
            "ctx.cr.set_field({}, ctx.fpscr.fcmpu({}, {}));",
            bf.0,
            f(fra),
            f(frb)
        )),
        Insn::Fcmpo { bf, fra, frb } => e.line(format!(
            "ctx.cr.set_field({}, ctx.fpscr.fcmpo({}, {}));",
            bf.0,
            f(fra),
            f(frb)
        )),
        Insn::Mcrfs { bf, bfa } => e.line(format!(
            "ctx.cr.set_field({}, ctx.fpscr.mcrfs({}));",
            bf.0, bfa.0
        )),
        Insn::Mffs { frt, rc } => e.set_f(frt, "ctx.fpscr.mffs()", rc),
        Insn::Mtfsf { flm, frb, l, w, rc } => {
            later_field(at, "mtfsf", l | w)?;
            e.line(format!("ctx.fpscr.mtfsf({flm:#04x}, {});", f(frb)));
            e.record_f(rc);
        }
        Insn::Mtfsfi { bf, u, w, rc } => {
            later_field(at, "mtfsfi", w)?;
            e.line(format!("ctx.fpscr.mtfsfi({bf}, {u:#x});"));
            e.record_f(rc);
        }
        Insn::Mtfsb0 { bt, rc } => {
            e.line(format!("ctx.fpscr.mtfsb0({});", bt.0));
            e.record_f(rc);
        }
        Insn::Mtfsb1 { bt, rc } => {
            e.line(format!("ctx.fpscr.mtfsb1({});", bt.0));
            e.record_f(rc);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Rejects the L and W fields of `mtfsf` and `mtfsfi`, which came after version 2.02 of the ISA:
/// in that version their bits are reserved.
fn later_field(at: u32, mnemonic: &'static str, value: u8) -> Result<(), Error> {
    if value != 0 {
        return Err(Error::InvalidForm {
            addr: at,
            mnemonic,
            why: "the L and W fields came after version 2.02 of the ISA",
        });
    }
    Ok(())
}
