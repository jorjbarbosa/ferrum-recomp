// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The condition register, special-purpose registers, the MSR and storage barriers.

use ferrum_decoder::{CrBit, Insn};
use ferrum_runtime::Spr;

use super::{Emitter, r};
use crate::error::Error;

/// Emits `insn` if it belongs to this family, and returns whether it did.
pub(super) fn emit(e: &mut Emitter<'_>, at: u32, insn: &Insn) -> Result<bool, Error> {
    match *insn {
        Insn::Mfcr { rt } => e.set(rt, "u64::from(ctx.cr.to_u32())"),
        // FXM has one bit set (the decoder accepts no other): that field in place, zeros
        // elsewhere, where Book I leaves the bits undefined.
        Insn::Mfocrf { rt, fxm } => {
            let n = fxm.leading_zeros();
            let shift = 28 - 4 * n;
            e.set(rt, format!("u64::from(ctx.cr.field({n})) << {shift}"));
        }
        Insn::Mtcrf { fxm, rs } => {
            e.open("{");
            e.line(format!("let v = {} as u32;", r(rs)));
            for n in 0..8u32 {
                if fxm & (0x80 >> n) != 0 {
                    let shift = 28 - 4 * n;
                    e.line(format!(
                        "ctx.cr.set_field({n}, (v >> {shift}) as u8 & 0xf);"
                    ));
                }
            }
            e.close("}");
        }
        Insn::Mcrf { bf, bfa } => {
            e.line(format!(
                "ctx.cr.set_field({}, ctx.cr.field({}));",
                bf.0, bfa.0
            ));
        }
        Insn::Crand { bt, ba, bb } => cr_op(e, bt, ba, bb, "{a} & {b}"),
        Insn::Crandc { bt, ba, bb } => cr_op(e, bt, ba, bb, "{a} & !{b}"),
        Insn::Creqv { bt, ba, bb } => cr_op(e, bt, ba, bb, "!({a} ^ {b})"),
        Insn::Crnand { bt, ba, bb } => cr_op(e, bt, ba, bb, "!({a} & {b})"),
        Insn::Crnor { bt, ba, bb } => cr_op(e, bt, ba, bb, "!({a} | {b})"),
        Insn::Cror { bt, ba, bb } => cr_op(e, bt, ba, bb, "{a} | {b}"),
        Insn::Crorc { bt, ba, bb } => cr_op(e, bt, ba, bb, "{a} | !{b}"),
        Insn::Crxor { bt, ba, bb } => cr_op(e, bt, ba, bb, "{a} ^ {b}"),
        Insn::Mfspr { rt, spr } => match Spr::for_mfspr(u32::from(spr)) {
            Some(Spr::Lr) => e.set(rt, "ctx.lr"),
            Some(Spr::Ctr) => e.set(rt, "ctx.ctr"),
            Some(spr) => e.set(rt, format!("ctx.mfspr(Spr::{spr:?})")),
            None => return Err(unmapped(at, "mfspr", spr)),
        },
        // `mftb` reads the time base as `mfspr` of TBL or TBU does; the decoder takes only those.
        Insn::Mftb { rt, tbr } => match Spr::for_mfspr(u32::from(tbr)) {
            Some(spr @ (Spr::Tbl | Spr::Tbu)) => e.set(rt, format!("ctx.mfspr(Spr::{spr:?})")),
            _ => return Err(unmapped(at, "mftb", tbr)),
        },
        Insn::Mtspr { spr, rs } => match Spr::for_mtspr(u32::from(spr)) {
            Some(Spr::Lr) => e.line(format!("ctx.lr = {};", r(rs))),
            Some(Spr::Ctr) => e.line(format!("ctx.ctr = {};", r(rs))),
            Some(spr) => e.line(format!("ctx.mtspr(Spr::{spr:?}, {});", r(rs))),
            None => return Err(unmapped(at, "mtspr", spr)),
        },
        Insn::Mfmsr { rt } => e.set(rt, "ctx.msr"),
        Insn::Mtmsr { rs, l } => e.line(format!("ctx.mtmsr({}, {});", r(rs), l != 0)),
        Insn::Mtmsrd { rs } => e.line(format!("ctx.mtmsrd({}, false);", r(rs))),
        Insn::Mtmsree { rs } => e.line(format!("ctx.mtmsrd({}, true);", r(rs))),
        // `lwsync` (L=1) orders all but stores before loads; `sync` and `ptesync` order everything.
        Insn::Sync { l: 1 } => fence(e, "AcqRel"),
        Insn::Sync { .. } => fence(e, "SeqCst"),
        Insn::Eieio {} => fence(e, "AcqRel"),
        // It orders instruction fetch, which recompiled code does not do.
        Insn::Isync {} => {}
        _ => return Ok(false),
    }
    Ok(true)
}

/// A condition register logical operation: bit `bt` from `op` over bits `ba` and `bb`.
fn cr_op(e: &mut Emitter<'_>, bt: CrBit, ba: CrBit, bb: CrBit, op: &str) {
    let a = format!("ctx.cr.bit({})", ba.0);
    let b = format!("ctx.cr.bit({})", bb.0);
    let value = op.replace("{a}", &a).replace("{b}", &b);
    e.line(format!("ctx.cr.set_bit({}, {value});", bt.0));
}

fn fence(e: &mut Emitter<'_>, ordering: &str) {
    e.line(format!(
        "std::sync::atomic::fence(std::sync::atomic::Ordering::{ordering});"
    ));
}

fn unmapped(addr: u32, op: &'static str, spr: u16) -> Error {
    Error::UnmappedSpr { addr, op, spr }
}
