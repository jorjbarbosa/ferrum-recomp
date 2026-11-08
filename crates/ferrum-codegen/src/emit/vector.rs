// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! VMX and VMX128: loads and stores, permutes, integer and floating-point arithmetic, compares
//! and the VSCR.
//!
//! Each instruction is one call of a helper of the runtime's `ops`, named after the instruction,
//! with `ctx.vscr` when the helper reads NJ and `&mut ctx.vscr` when it may set SAT. A VMX128 form
//! that only widens the register fields calls the VMX helper; the others call their own helper,
//! whose doc gives the order of the operands. A compare with Rc = 1 then sets CR6.

use ferrum_decoder::{Gpr, Insn, Vr};

use super::Emitter;
use super::memory::Address;

#[cfg(test)]
mod tests;

/// Emits `insn` if it belongs to this family, and returns whether it did.
pub(super) fn emit(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    memory(e, insn)
        || moves(e, insn)
        || integer(e, insn)
        || saturating(e, insn)
        || four_operands(e, insn)
        || float(e, insn)
        || immediates(e, insn)
        || compare(e, insn)
        || vmx128(e, insn)
}

/// VR `n`.
fn v(n: Vr) -> String {
    format!("ctx.v[{}]", n.0)
}

/// What a helper does with the VSCR.
#[derive(Clone, Copy)]
enum Vscr {
    /// Nothing.
    None,
    /// Reads NJ: the floating-point helpers.
    Read,
    /// May set SAT: the saturating helpers.
    Write,
}

/// `vD = ops::<name>(vscr, args...)`.
fn call(e: &mut Emitter<'_>, vd: Vr, vscr: Vscr, name: &str, args: &[String]) {
    let mut all: Vec<String> = match vscr {
        Vscr::None => Vec::new(),
        Vscr::Read => vec!["ctx.vscr".to_owned()],
        Vscr::Write => vec!["&mut ctx.vscr".to_owned()],
    };
    all.extend_from_slice(args);
    e.line(format!(
        "ctx.v[{}] = ops::{name}({});",
        vd.0,
        all.join(", ")
    ));
}

/// The effective address `(rA|0) + rB`, a `u32`.
fn ea(ra: Gpr, rb: Gpr) -> String {
    Address::Indexed(ra, rb).ea()
}

/// The loads and stores, `lvsl` and `lvsr`, and the stream hints.
fn memory(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    match *insn {
        // The whole aligned quadword: lvx, and the element loads, whose other elements the ISA
        // leaves undefined.
        Insn::Lvx { vd, ra, rb }
        | Insn::Lvxl { vd, ra, rb }
        | Insn::Lvebx { vd, ra, rb }
        | Insn::Lvehx { vd, ra, rb }
        | Insn::Lvewx { vd, ra, rb }
        | Insn::Lvx128 { vd, ra, rb }
        | Insn::Lvxl128 { vd, ra, rb }
        | Insn::Lvewx128 { vd, ra, rb } => e.line(format!(
            "ctx.v[{}] = mem.read_v128({} & !0xf);",
            vd.0,
            ea(ra, rb)
        )),
        Insn::Stvx { vs, ra, rb }
        | Insn::Stvxl { vs, ra, rb }
        | Insn::Stvx128 { vs, ra, rb }
        | Insn::Stvxl128 { vs, ra, rb } => {
            e.line(format!("mem.write_v128({} & !0xf, {});", ea(ra, rb), v(vs)))
        }
        Insn::Stvebx { vs, ra, rb } => store(e, "stvebx", vs, ra, rb),
        Insn::Stvehx { vs, ra, rb } => store(e, "stvehx", vs, ra, rb),
        Insn::Stvewx { vs, ra, rb } | Insn::Stvewx128 { vs, ra, rb } => {
            store(e, "stvewx", vs, ra, rb);
        }
        Insn::Lvlx { vd, ra, rb }
        | Insn::Lvlxl { vd, ra, rb }
        | Insn::Lvlx128 { vd, ra, rb }
        | Insn::Lvlxl128 { vd, ra, rb } => load(e, "lvlx", vd, ra, rb),
        Insn::Lvrx { vd, ra, rb }
        | Insn::Lvrxl { vd, ra, rb }
        | Insn::Lvrx128 { vd, ra, rb }
        | Insn::Lvrxl128 { vd, ra, rb } => load(e, "lvrx", vd, ra, rb),
        Insn::Stvlx { vs, ra, rb }
        | Insn::Stvlxl { vs, ra, rb }
        | Insn::Stvlx128 { vs, ra, rb }
        | Insn::Stvlxl128 { vs, ra, rb } => store(e, "stvlx", vs, ra, rb),
        Insn::Stvrx { vs, ra, rb }
        | Insn::Stvrxl { vs, ra, rb }
        | Insn::Stvrx128 { vs, ra, rb }
        | Insn::Stvrxl128 { vs, ra, rb } => store(e, "stvrx", vs, ra, rb),
        Insn::Lvsl { vd, ra, rb } | Insn::Lvsl128 { vd, ra, rb } => {
            call(e, vd, Vscr::None, "lvsl", &[ea(ra, rb)]);
        }
        Insn::Lvsr { vd, ra, rb } | Insn::Lvsr128 { vd, ra, rb } => {
            call(e, vd, Vscr::None, "lvsr", &[ea(ra, rb)]);
        }
        // Hints about data streams change no architected state.
        Insn::Dst { .. } | Insn::Dstst { .. } | Insn::Dss { .. } => {}
        _ => return false,
    }
    true
}

/// `vD = ops::<name>(mem, EA)`.
fn load(e: &mut Emitter<'_>, name: &str, vd: Vr, ra: Gpr, rb: Gpr) {
    call(e, vd, Vscr::None, name, &["mem".to_owned(), ea(ra, rb)]);
}

/// `ops::<name>(mem, EA, vS)`.
fn store(e: &mut Emitter<'_>, name: &str, vs: Vr, ra: Gpr, rb: Gpr) {
    e.line(format!("ops::{name}(mem, {}, {});", ea(ra, rb), v(vs)));
}

/// The VSCR moves and the instructions of one source register that move elements.
fn moves(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, vd, vb) = match *insn {
        Insn::Mfvscr { vd } => {
            e.line(format!("ctx.v[{}] = ctx.vscr.mfvscr();", vd.0));
            return true;
        }
        Insn::Mtvscr { vb } => {
            e.line(format!("ctx.vscr.mtvscr({});", v(vb)));
            return true;
        }
        Insn::Vupkhsb { vd, vb } => ("vupkhsb", vd, vb),
        Insn::Vupklsb { vd, vb } => ("vupklsb", vd, vb),
        Insn::Vupkhsh { vd, vb } => ("vupkhsh", vd, vb),
        Insn::Vupklsh { vd, vb } => ("vupklsh", vd, vb),
        Insn::Vupkhpx { vd, vb } => ("vupkhpx", vd, vb),
        Insn::Vupklpx { vd, vb } => ("vupklpx", vd, vb),
        _ => return false,
    };
    call(e, vd, Vscr::None, name, &[v(vb)]);
    true
}

/// The instructions of two source registers whose helpers neither read nor write the VSCR.
fn integer(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, vd, va, vb) = match *insn {
        Insn::Vaddubm { vd, va, vb } => ("vaddubm", vd, va, vb),
        Insn::Vadduhm { vd, va, vb } => ("vadduhm", vd, va, vb),
        Insn::Vadduwm { vd, va, vb } => ("vadduwm", vd, va, vb),
        Insn::Vsububm { vd, va, vb } => ("vsububm", vd, va, vb),
        Insn::Vsubuhm { vd, va, vb } => ("vsubuhm", vd, va, vb),
        Insn::Vsubuwm { vd, va, vb } => ("vsubuwm", vd, va, vb),
        Insn::Vaddcuw { vd, va, vb } => ("vaddcuw", vd, va, vb),
        Insn::Vsubcuw { vd, va, vb } => ("vsubcuw", vd, va, vb),
        Insn::Vavgub { vd, va, vb } => ("vavgub", vd, va, vb),
        Insn::Vavguh { vd, va, vb } => ("vavguh", vd, va, vb),
        Insn::Vavguw { vd, va, vb } => ("vavguw", vd, va, vb),
        Insn::Vavgsb { vd, va, vb } => ("vavgsb", vd, va, vb),
        Insn::Vavgsh { vd, va, vb } => ("vavgsh", vd, va, vb),
        Insn::Vavgsw { vd, va, vb } => ("vavgsw", vd, va, vb),
        Insn::Vmaxub { vd, va, vb } => ("vmaxub", vd, va, vb),
        Insn::Vmaxuh { vd, va, vb } => ("vmaxuh", vd, va, vb),
        Insn::Vmaxuw { vd, va, vb } => ("vmaxuw", vd, va, vb),
        Insn::Vmaxsb { vd, va, vb } => ("vmaxsb", vd, va, vb),
        Insn::Vmaxsh { vd, va, vb } => ("vmaxsh", vd, va, vb),
        Insn::Vmaxsw { vd, va, vb } => ("vmaxsw", vd, va, vb),
        Insn::Vminub { vd, va, vb } => ("vminub", vd, va, vb),
        Insn::Vminuh { vd, va, vb } => ("vminuh", vd, va, vb),
        Insn::Vminuw { vd, va, vb } => ("vminuw", vd, va, vb),
        Insn::Vminsb { vd, va, vb } => ("vminsb", vd, va, vb),
        Insn::Vminsh { vd, va, vb } => ("vminsh", vd, va, vb),
        Insn::Vminsw { vd, va, vb } => ("vminsw", vd, va, vb),
        Insn::Vmuleub { vd, va, vb } => ("vmuleub", vd, va, vb),
        Insn::Vmuleuh { vd, va, vb } => ("vmuleuh", vd, va, vb),
        Insn::Vmulesb { vd, va, vb } => ("vmulesb", vd, va, vb),
        Insn::Vmulesh { vd, va, vb } => ("vmulesh", vd, va, vb),
        Insn::Vmuloub { vd, va, vb } => ("vmuloub", vd, va, vb),
        Insn::Vmulouh { vd, va, vb } => ("vmulouh", vd, va, vb),
        Insn::Vmulosb { vd, va, vb } => ("vmulosb", vd, va, vb),
        Insn::Vmulosh { vd, va, vb } => ("vmulosh", vd, va, vb),
        Insn::Vand { vd, va, vb } => ("vand", vd, va, vb),
        Insn::Vandc { vd, va, vb } => ("vandc", vd, va, vb),
        Insn::Vor { vd, va, vb } => ("vor", vd, va, vb),
        Insn::Vxor { vd, va, vb } => ("vxor", vd, va, vb),
        Insn::Vnor { vd, va, vb } => ("vnor", vd, va, vb),
        Insn::Vrlb { vd, va, vb } => ("vrlb", vd, va, vb),
        Insn::Vrlh { vd, va, vb } => ("vrlh", vd, va, vb),
        Insn::Vrlw { vd, va, vb } => ("vrlw", vd, va, vb),
        Insn::Vslb { vd, va, vb } => ("vslb", vd, va, vb),
        Insn::Vslh { vd, va, vb } => ("vslh", vd, va, vb),
        Insn::Vslw { vd, va, vb } => ("vslw", vd, va, vb),
        Insn::Vsrb { vd, va, vb } => ("vsrb", vd, va, vb),
        Insn::Vsrh { vd, va, vb } => ("vsrh", vd, va, vb),
        Insn::Vsrw { vd, va, vb } => ("vsrw", vd, va, vb),
        Insn::Vsrab { vd, va, vb } => ("vsrab", vd, va, vb),
        Insn::Vsrah { vd, va, vb } => ("vsrah", vd, va, vb),
        Insn::Vsraw { vd, va, vb } => ("vsraw", vd, va, vb),
        Insn::Vsl { vd, va, vb } => ("vsl", vd, va, vb),
        Insn::Vsr { vd, va, vb } => ("vsr", vd, va, vb),
        Insn::Vslo { vd, va, vb } => ("vslo", vd, va, vb),
        Insn::Vsro { vd, va, vb } => ("vsro", vd, va, vb),
        Insn::Vmrghb { vd, va, vb } => ("vmrghb", vd, va, vb),
        Insn::Vmrghh { vd, va, vb } => ("vmrghh", vd, va, vb),
        Insn::Vmrghw { vd, va, vb } => ("vmrghw", vd, va, vb),
        Insn::Vmrglb { vd, va, vb } => ("vmrglb", vd, va, vb),
        Insn::Vmrglh { vd, va, vb } => ("vmrglh", vd, va, vb),
        Insn::Vmrglw { vd, va, vb } => ("vmrglw", vd, va, vb),
        Insn::Vpkuhum { vd, va, vb } => ("vpkuhum", vd, va, vb),
        Insn::Vpkuwum { vd, va, vb } => ("vpkuwum", vd, va, vb),
        Insn::Vpkpx { vd, va, vb } => ("vpkpx", vd, va, vb),
        _ => return false,
    };
    call(e, vd, Vscr::None, name, &[v(va), v(vb)]);
    true
}

/// The saturating instructions of two source registers.
fn saturating(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, vd, va, vb) = match *insn {
        Insn::Vaddubs { vd, va, vb } => ("vaddubs", vd, va, vb),
        Insn::Vaddsbs { vd, va, vb } => ("vaddsbs", vd, va, vb),
        Insn::Vadduhs { vd, va, vb } => ("vadduhs", vd, va, vb),
        Insn::Vaddshs { vd, va, vb } => ("vaddshs", vd, va, vb),
        Insn::Vadduws { vd, va, vb } => ("vadduws", vd, va, vb),
        Insn::Vaddsws { vd, va, vb } => ("vaddsws", vd, va, vb),
        Insn::Vsububs { vd, va, vb } => ("vsububs", vd, va, vb),
        Insn::Vsubsbs { vd, va, vb } => ("vsubsbs", vd, va, vb),
        Insn::Vsubuhs { vd, va, vb } => ("vsubuhs", vd, va, vb),
        Insn::Vsubshs { vd, va, vb } => ("vsubshs", vd, va, vb),
        Insn::Vsubuws { vd, va, vb } => ("vsubuws", vd, va, vb),
        Insn::Vsubsws { vd, va, vb } => ("vsubsws", vd, va, vb),
        Insn::Vsumsws { vd, va, vb } => ("vsumsws", vd, va, vb),
        Insn::Vsum2sws { vd, va, vb } => ("vsum2sws", vd, va, vb),
        Insn::Vsum4ubs { vd, va, vb } => ("vsum4ubs", vd, va, vb),
        Insn::Vsum4sbs { vd, va, vb } => ("vsum4sbs", vd, va, vb),
        Insn::Vsum4shs { vd, va, vb } => ("vsum4shs", vd, va, vb),
        Insn::Vpkuhus { vd, va, vb } => ("vpkuhus", vd, va, vb),
        Insn::Vpkuwus { vd, va, vb } => ("vpkuwus", vd, va, vb),
        Insn::Vpkshus { vd, va, vb } => ("vpkshus", vd, va, vb),
        Insn::Vpkswus { vd, va, vb } => ("vpkswus", vd, va, vb),
        Insn::Vpkshss { vd, va, vb } => ("vpkshss", vd, va, vb),
        Insn::Vpkswss { vd, va, vb } => ("vpkswss", vd, va, vb),
        _ => return false,
    };
    call(e, vd, Vscr::Write, name, &[v(va), v(vb)]);
    true
}

/// The VA-form instructions of three source registers, and `vsldoi`.
fn four_operands(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, vscr, vd, args) = match *insn {
        Insn::Vmhaddshs { vd, va, vb, vc } => ("vmhaddshs", Vscr::Write, vd, [va, vb, vc]),
        Insn::Vmhraddshs { vd, va, vb, vc } => ("vmhraddshs", Vscr::Write, vd, [va, vb, vc]),
        Insn::Vmladduhm { vd, va, vb, vc } => ("vmladduhm", Vscr::None, vd, [va, vb, vc]),
        Insn::Vmsumubm { vd, va, vb, vc } => ("vmsumubm", Vscr::None, vd, [va, vb, vc]),
        Insn::Vmsummbm { vd, va, vb, vc } => ("vmsummbm", Vscr::None, vd, [va, vb, vc]),
        Insn::Vmsumuhm { vd, va, vb, vc } => ("vmsumuhm", Vscr::None, vd, [va, vb, vc]),
        Insn::Vmsumuhs { vd, va, vb, vc } => ("vmsumuhs", Vscr::Write, vd, [va, vb, vc]),
        Insn::Vmsumshm { vd, va, vb, vc } => ("vmsumshm", Vscr::None, vd, [va, vb, vc]),
        Insn::Vmsumshs { vd, va, vb, vc } => ("vmsumshs", Vscr::Write, vd, [va, vb, vc]),
        Insn::Vsel { vd, va, vb, vc } => ("vsel", Vscr::None, vd, [va, vb, vc]),
        Insn::Vperm { vd, va, vb, vc } => ("vperm", Vscr::None, vd, [va, vb, vc]),
        // vmaddfp vD, vA, vC, vB computes vA × vC + vB: the helper takes them in that order.
        Insn::Vmaddfp { vd, va, vc, vb } => ("vmaddfp", Vscr::Read, vd, [va, vc, vb]),
        Insn::Vnmsubfp { vd, va, vc, vb } => ("vnmsubfp", Vscr::Read, vd, [va, vc, vb]),
        Insn::Vsldoi { vd, va, vb, shb } => {
            call(
                e,
                vd,
                Vscr::None,
                "vsldoi",
                &[v(va), v(vb), shb.to_string()],
            );
            return true;
        }
        _ => return false,
    };
    call(e, vd, vscr, name, &args.map(v));
    true
}

/// The floating-point instructions of one or two source registers.
fn float(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, vd, args) = match *insn {
        Insn::Vaddfp { vd, va, vb } => ("vaddfp", vd, vec![va, vb]),
        Insn::Vsubfp { vd, va, vb } => ("vsubfp", vd, vec![va, vb]),
        Insn::Vmaxfp { vd, va, vb } => ("vmaxfp", vd, vec![va, vb]),
        Insn::Vminfp { vd, va, vb } => ("vminfp", vd, vec![va, vb]),
        Insn::Vrefp { vd, vb } => ("vrefp", vd, vec![vb]),
        Insn::Vrsqrtefp { vd, vb } => ("vrsqrtefp", vd, vec![vb]),
        Insn::Vexptefp { vd, vb } => ("vexptefp", vd, vec![vb]),
        Insn::Vlogefp { vd, vb } => ("vlogefp", vd, vec![vb]),
        Insn::Vrfin { vd, vb } => ("vrfin", vd, vec![vb]),
        Insn::Vrfiz { vd, vb } => ("vrfiz", vd, vec![vb]),
        Insn::Vrfip { vd, vb } => ("vrfip", vd, vec![vb]),
        Insn::Vrfim { vd, vb } => ("vrfim", vd, vec![vb]),
        _ => return false,
    };
    let args: Vec<String> = args.into_iter().map(v).collect();
    call(e, vd, Vscr::Read, name, &args);
    true
}

/// The instructions with an immediate: splats and the conversions.
fn immediates(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    match *insn {
        Insn::Vspltb { vd, vb, uim } => {
            call(e, vd, Vscr::None, "vspltb", &[v(vb), uim.to_string()])
        }
        Insn::Vsplth { vd, vb, uim } => {
            call(e, vd, Vscr::None, "vsplth", &[v(vb), uim.to_string()])
        }
        Insn::Vspltw { vd, vb, uim } => {
            call(e, vd, Vscr::None, "vspltw", &[v(vb), uim.to_string()])
        }
        Insn::Vspltisb { vd, sim } => call(e, vd, Vscr::None, "vspltisb", &[sim.to_string()]),
        Insn::Vspltish { vd, sim } => call(e, vd, Vscr::None, "vspltish", &[sim.to_string()]),
        Insn::Vspltisw { vd, sim } => call(e, vd, Vscr::None, "vspltisw", &[sim.to_string()]),
        Insn::Vcfsx { vd, vb, uim } => call(e, vd, Vscr::None, "vcfsx", &[v(vb), uim.to_string()]),
        Insn::Vcfux { vd, vb, uim } => call(e, vd, Vscr::None, "vcfux", &[v(vb), uim.to_string()]),
        Insn::Vctsxs { vd, vb, uim } => {
            call(e, vd, Vscr::Write, "vctsxs", &[v(vb), uim.to_string()]);
        }
        Insn::Vctuxs { vd, vb, uim } => {
            call(e, vd, Vscr::Write, "vctuxs", &[v(vb), uim.to_string()]);
        }
        _ => return false,
    }
    true
}

/// The compares; with Rc = 1 they set CR6.
fn compare(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, vscr, vd, va, vb, rc) = match *insn {
        Insn::Vcmpequb { vd, va, vb, rc } => ("vcmpequb", Vscr::None, vd, va, vb, rc),
        Insn::Vcmpequh { vd, va, vb, rc } => ("vcmpequh", Vscr::None, vd, va, vb, rc),
        Insn::Vcmpequw { vd, va, vb, rc } | Insn::Vcmpequw128 { vd, va, vb, rc } => {
            ("vcmpequw", Vscr::None, vd, va, vb, rc)
        }
        Insn::Vcmpgtub { vd, va, vb, rc } => ("vcmpgtub", Vscr::None, vd, va, vb, rc),
        Insn::Vcmpgtuh { vd, va, vb, rc } => ("vcmpgtuh", Vscr::None, vd, va, vb, rc),
        Insn::Vcmpgtuw { vd, va, vb, rc } => ("vcmpgtuw", Vscr::None, vd, va, vb, rc),
        Insn::Vcmpgtsb { vd, va, vb, rc } => ("vcmpgtsb", Vscr::None, vd, va, vb, rc),
        Insn::Vcmpgtsh { vd, va, vb, rc } => ("vcmpgtsh", Vscr::None, vd, va, vb, rc),
        Insn::Vcmpgtsw { vd, va, vb, rc } => ("vcmpgtsw", Vscr::None, vd, va, vb, rc),
        Insn::Vcmpeqfp { vd, va, vb, rc } | Insn::Vcmpeqfp128 { vd, va, vb, rc } => {
            ("vcmpeqfp", Vscr::Read, vd, va, vb, rc)
        }
        Insn::Vcmpgefp { vd, va, vb, rc } | Insn::Vcmpgefp128 { vd, va, vb, rc } => {
            ("vcmpgefp", Vscr::Read, vd, va, vb, rc)
        }
        Insn::Vcmpgtfp { vd, va, vb, rc } | Insn::Vcmpgtfp128 { vd, va, vb, rc } => {
            ("vcmpgtfp", Vscr::Read, vd, va, vb, rc)
        }
        Insn::Vcmpbfp { vd, va, vb, rc } | Insn::Vcmpbfp128 { vd, va, vb, rc } => {
            ("vcmpbfp", Vscr::Read, vd, va, vb, rc)
        }
        _ => return false,
    };
    call(e, vd, vscr, name, &[v(va), v(vb)]);
    if rc {
        let record = if name == "vcmpbfp" {
            "vcmpbfp_cr6"
        } else {
            "vcmp_cr6"
        };
        e.line(format!("ctx.cr.set_field(6, ops::{record}({}));", v(vd)));
    }
    true
}

/// The VMX128 instructions other than the loads, stores and compares.
fn vmx128(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    match *insn {
        Insn::Vsldoi128 { vd, va, vb, sh } => {
            call(e, vd, Vscr::None, "vsldoi", &[v(va), v(vb), sh.to_string()]);
        }
        Insn::Vperm128 { vd, va, vb, vc } => {
            call(e, vd, Vscr::None, "vperm", &[v(va), v(vb), v(vc)])
        }
        // vD is also an operand: the addend of vmaddfp128 and vnmsubfp128, the multiplicand of
        // vmaddcfp128, and the selector of vsel128.
        Insn::Vmaddfp128 { vd, va, vb } => {
            call(e, vd, Vscr::Read, "vmaddfp", &[v(va), v(vb), v(vd)])
        }
        Insn::Vmaddcfp128 { vd, va, vb } => {
            call(e, vd, Vscr::Read, "vmaddfp", &[v(va), v(vd), v(vb)])
        }
        Insn::Vnmsubfp128 { vd, va, vb } => {
            call(e, vd, Vscr::Read, "vnmsubfp", &[v(va), v(vb), v(vd)])
        }
        Insn::Vsel128 { vd, va, vb } => call(e, vd, Vscr::None, "vsel", &[v(va), v(vb), v(vd)]),
        Insn::Vupkhsb128 { vd, vb, ignored } => {
            let name = if ignored == 0x60 {
                "vupkhsh"
            } else {
                "vupkhsb"
            };
            call(e, vd, Vscr::None, name, &[v(vb)]);
        }
        Insn::Vupklsb128 { vd, vb, ignored } => {
            let name = if ignored == 0x60 {
                "vupklsh"
            } else {
                "vupklsb"
            };
            call(e, vd, Vscr::None, name, &[v(vb)]);
        }
        // The scale is the raw 5-bit field, which objdump prints as signed for two of them.
        Insn::Vcfpsxws128 { vd, vb, simm } => {
            call(e, vd, Vscr::Write, "vctsxs", &[v(vb), field5(simm)]);
        }
        Insn::Vcfpuxws128 { vd, vb, uimm } => {
            call(e, vd, Vscr::Write, "vctuxs", &[v(vb), uimm.to_string()]);
        }
        Insn::Vcsxwfp128 { vd, vb, simm } => {
            call(e, vd, Vscr::None, "vcfsx", &[v(vb), field5(simm)])
        }
        Insn::Vcuxwfp128 { vd, vb, uimm } => {
            call(e, vd, Vscr::None, "vcfux", &[v(vb), uimm.to_string()]);
        }
        Insn::Vspltw128 { vd, vb, uimm } => {
            call(e, vd, Vscr::None, "vspltw", &[v(vb), uimm.to_string()])
        }
        Insn::Vspltisw128 { vd, simm, .. } => {
            call(e, vd, Vscr::None, "vspltisw", &[simm.to_string()])
        }
        Insn::Vpermwi128 { vd, vb, perm } => {
            call(e, vd, Vscr::None, "vpermwi128", &[v(vb), perm.to_string()]);
        }
        Insn::Vrlimi128 { vd, vb, imm, z } => {
            let args = [v(vd), v(vb), imm.to_string(), z.to_string()];
            call(e, vd, Vscr::None, "vrlimi128", &args);
        }
        Insn::Vpkd3d128 { vd, vb, imm, z } => pack_d3d(e, vd, vb, imm, z),
        Insn::Vupkd3d128 { vd, vb, uimm } => {
            let kind = uimm >> 2;
            if kind > 5 {
                e.missing(format!("vupkd3d128 (type {kind})"));
            } else {
                call(e, vd, Vscr::None, "vupkd3d128", &[v(vb), kind.to_string()]);
            }
        }
        _ => return widened(e, insn),
    }
    true
}

/// The raw 5 bits of a field the decoder sign-extends.
fn field5(simm: i16) -> String {
    (simm & 0x1F).to_string()
}

/// `vpkd3d128 vD, vB, type, mask, shift`: IMM holds the type and the mask, z the shift. Types 6
/// and 7 and mask 0 have no known meaning; they count as opcodes without `emit_*`.
fn pack_d3d(e: &mut Emitter<'_>, vd: Vr, vb: Vr, imm: u8, z: u8) {
    let (kind, mask) = (imm >> 2, imm & 3);
    if kind > 5 {
        e.missing(format!("vpkd3d128 (type {kind})"));
    } else if mask == 0 {
        e.missing("vpkd3d128 (mask 0)");
    } else {
        let args = [
            v(vd),
            v(vb),
            kind.to_string(),
            mask.to_string(),
            z.to_string(),
        ];
        call(e, vd, Vscr::None, "vpkd3d128", &args);
    }
}

/// The VMX128 forms that only widen the register fields of a VMX instruction.
fn widened(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (name, vscr, vd, args) = match *insn {
        Insn::Vaddfp128 { vd, va, vb } => ("vaddfp", Vscr::Read, vd, vec![va, vb]),
        Insn::Vsubfp128 { vd, va, vb } => ("vsubfp", Vscr::Read, vd, vec![va, vb]),
        Insn::Vmulfp128 { vd, va, vb } => ("vmulfp128", Vscr::Read, vd, vec![va, vb]),
        Insn::Vmaxfp128 { vd, va, vb } => ("vmaxfp", Vscr::Read, vd, vec![va, vb]),
        Insn::Vminfp128 { vd, va, vb } => ("vminfp", Vscr::Read, vd, vec![va, vb]),
        Insn::Vmsum3fp128 { vd, va, vb } => ("vmsum3fp128", Vscr::Read, vd, vec![va, vb]),
        Insn::Vmsum4fp128 { vd, va, vb } => ("vmsum4fp128", Vscr::Read, vd, vec![va, vb]),
        Insn::Vrefp128 { vd, vb, .. } => ("vrefp", Vscr::Read, vd, vec![vb]),
        Insn::Vrsqrtefp128 { vd, vb, .. } => ("vrsqrtefp", Vscr::Read, vd, vec![vb]),
        Insn::Vexptefp128 { vd, vb, .. } => ("vexptefp", Vscr::Read, vd, vec![vb]),
        Insn::Vlogefp128 { vd, vb, .. } => ("vlogefp", Vscr::Read, vd, vec![vb]),
        Insn::Vrfin128 { vd, vb, .. } => ("vrfin", Vscr::Read, vd, vec![vb]),
        Insn::Vrfiz128 { vd, vb, .. } => ("vrfiz", Vscr::Read, vd, vec![vb]),
        Insn::Vrfip128 { vd, vb, .. } => ("vrfip", Vscr::Read, vd, vec![vb]),
        Insn::Vrfim128 { vd, vb, .. } => ("vrfim", Vscr::Read, vd, vec![vb]),
        Insn::Vand128 { vd, va, vb } => ("vand", Vscr::None, vd, vec![va, vb]),
        Insn::Vandc128 { vd, va, vb } => ("vandc", Vscr::None, vd, vec![va, vb]),
        Insn::Vor128 { vd, va, vb } => ("vor", Vscr::None, vd, vec![va, vb]),
        Insn::Vxor128 { vd, va, vb } => ("vxor", Vscr::None, vd, vec![va, vb]),
        Insn::Vnor128 { vd, va, vb } => ("vnor", Vscr::None, vd, vec![va, vb]),
        Insn::Vslo128 { vd, va, vb } => ("vslo", Vscr::None, vd, vec![va, vb]),
        Insn::Vsro128 { vd, va, vb } => ("vsro", Vscr::None, vd, vec![va, vb]),
        Insn::Vrlw128 { vd, va, vb } => ("vrlw", Vscr::None, vd, vec![va, vb]),
        Insn::Vslw128 { vd, va, vb } => ("vslw", Vscr::None, vd, vec![va, vb]),
        Insn::Vsraw128 { vd, va, vb } => ("vsraw", Vscr::None, vd, vec![va, vb]),
        Insn::Vsrw128 { vd, va, vb } => ("vsrw", Vscr::None, vd, vec![va, vb]),
        Insn::Vmrghw128 { vd, va, vb } => ("vmrghw", Vscr::None, vd, vec![va, vb]),
        Insn::Vmrglw128 { vd, va, vb } => ("vmrglw", Vscr::None, vd, vec![va, vb]),
        Insn::Vpkuhum128 { vd, va, vb } => ("vpkuhum", Vscr::None, vd, vec![va, vb]),
        Insn::Vpkuwum128 { vd, va, vb } => ("vpkuwum", Vscr::None, vd, vec![va, vb]),
        Insn::Vpkuhus128 { vd, va, vb } => ("vpkuhus", Vscr::Write, vd, vec![va, vb]),
        Insn::Vpkuwus128 { vd, va, vb } => ("vpkuwus", Vscr::Write, vd, vec![va, vb]),
        Insn::Vpkshus128 { vd, va, vb } => ("vpkshus", Vscr::Write, vd, vec![va, vb]),
        Insn::Vpkswus128 { vd, va, vb } => ("vpkswus", Vscr::Write, vd, vec![va, vb]),
        Insn::Vpkshss128 { vd, va, vb } => ("vpkshss", Vscr::Write, vd, vec![va, vb]),
        Insn::Vpkswss128 { vd, va, vb } => ("vpkswss", Vscr::Write, vd, vec![va, vb]),
        _ => return false,
    };
    let args: Vec<String> = args.into_iter().map(v).collect();
    call(e, vd, vscr, name, &args);
    true
}
