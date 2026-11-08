// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The text of every VMX and VMX128 emitter, and a check that every vector row of the decoder
//! has one.

use std::collections::BTreeMap;

use ferrum_analysis::{Code, Function, SaveRestore};
use ferrum_decoder::{Form, Gpr, Insn, OPCODES, Vr, decode};

use crate::emit::{Emitter, emit};
use crate::error::Error;
use crate::program::Program;

/// The statements `insn` becomes, without indentation, or the error.
fn text(insn: Insn) -> Result<String, Error> {
    let bytes = insn.encode().to_be_bytes();
    let routines = SaveRestore::new();
    let function = Function {
        addr: 0x8200_0000,
        size: 4,
    };
    let program = Program::new(Code::new(0x8200_0000, &bytes), [function], &routines);
    let mut e = Emitter::new(&program, function, 0..=u32::MAX);
    emit(&mut e, 0x8200_0000, &insn)?;
    let text = e.finish()?;
    Ok(text.lines().map(str::trim).collect::<Vec<_>>().join("\n"))
}

const D: Vr = Vr(1);
const A: Vr = Vr(2);
const B: Vr = Vr(3);
const C: Vr = Vr(4);
/// Registers only VMX128 can name.
const D7: Vr = Vr(100);
const A7: Vr = Vr(64);
const B7: Vr = Vr(127);
const R0: Gpr = Gpr(0);
const R3: Gpr = Gpr(3);
const R4: Gpr = Gpr(4);

/// A list of `(instruction, text)` pairs, one line each, which rustfmt leaves alone.
macro_rules! cases {
    ($($variant:ident { $($field:ident: $value:expr),* } => $expected:expr;)*) => {
        vec![$((Insn::$variant { $($field: $value),* }, $expected)),*]
    };
}

fn check(cases: Vec<(Insn, &str)>) {
    for (insn, expected) in cases {
        assert_eq!(text(insn).unwrap(), expected, "{insn:?}");
    }
}

/// `(rA|0) + rB` with rA = r3 and rB = r4.
const EA: &str = "(ctx.r[3] as u32).wrapping_add((ctx.r[4] as u32))";

#[test]
fn loads_and_stores_mask_or_pass_the_effective_address() {
    let quad = |vd: u8| format!("ctx.v[{vd}] = mem.read_v128({EA} & !0xf);");
    let store = |name: &str, vs: u8| format!("ops::{name}(mem, {EA}, ctx.v[{vs}]);");
    let helper = |name: &str, vd: u8| format!("ctx.v[{vd}] = ops::{name}(mem, {EA});");
    let quad_store = |vs: u8| format!("mem.write_v128({EA} & !0xf, ctx.v[{vs}]);");
    let cases: Vec<(Insn, String)> = vec![
        (
            Insn::Lvx {
                vd: D,
                ra: R3,
                rb: R4,
            },
            quad(1),
        ),
        (
            Insn::Lvxl {
                vd: D,
                ra: R3,
                rb: R4,
            },
            quad(1),
        ),
        (
            Insn::Lvebx {
                vd: D,
                ra: R3,
                rb: R4,
            },
            quad(1),
        ),
        (
            Insn::Lvehx {
                vd: D,
                ra: R3,
                rb: R4,
            },
            quad(1),
        ),
        (
            Insn::Lvewx {
                vd: D,
                ra: R3,
                rb: R4,
            },
            quad(1),
        ),
        (
            Insn::Lvx128 {
                vd: D7,
                ra: R3,
                rb: R4,
            },
            quad(100),
        ),
        (
            Insn::Lvxl128 {
                vd: D7,
                ra: R3,
                rb: R4,
            },
            quad(100),
        ),
        (
            Insn::Lvewx128 {
                vd: D7,
                ra: R3,
                rb: R4,
            },
            quad(100),
        ),
        (
            Insn::Stvx {
                vs: D,
                ra: R3,
                rb: R4,
            },
            quad_store(1),
        ),
        (
            Insn::Stvxl {
                vs: D,
                ra: R3,
                rb: R4,
            },
            quad_store(1),
        ),
        (
            Insn::Stvx128 {
                vs: D7,
                ra: R3,
                rb: R4,
            },
            quad_store(100),
        ),
        (
            Insn::Stvxl128 {
                vs: D7,
                ra: R3,
                rb: R4,
            },
            quad_store(100),
        ),
        (
            Insn::Stvebx {
                vs: D,
                ra: R3,
                rb: R4,
            },
            store("stvebx", 1),
        ),
        (
            Insn::Stvehx {
                vs: D,
                ra: R3,
                rb: R4,
            },
            store("stvehx", 1),
        ),
        (
            Insn::Stvewx {
                vs: D,
                ra: R3,
                rb: R4,
            },
            store("stvewx", 1),
        ),
        (
            Insn::Stvewx128 {
                vs: D7,
                ra: R3,
                rb: R4,
            },
            store("stvewx", 100),
        ),
        (
            Insn::Lvlx {
                vd: D,
                ra: R3,
                rb: R4,
            },
            helper("lvlx", 1),
        ),
        (
            Insn::Lvlxl {
                vd: D,
                ra: R3,
                rb: R4,
            },
            helper("lvlx", 1),
        ),
        (
            Insn::Lvlx128 {
                vd: D7,
                ra: R3,
                rb: R4,
            },
            helper("lvlx", 100),
        ),
        (
            Insn::Lvlxl128 {
                vd: D7,
                ra: R3,
                rb: R4,
            },
            helper("lvlx", 100),
        ),
        (
            Insn::Lvrx {
                vd: D,
                ra: R3,
                rb: R4,
            },
            helper("lvrx", 1),
        ),
        (
            Insn::Lvrxl {
                vd: D,
                ra: R3,
                rb: R4,
            },
            helper("lvrx", 1),
        ),
        (
            Insn::Lvrx128 {
                vd: D7,
                ra: R3,
                rb: R4,
            },
            helper("lvrx", 100),
        ),
        (
            Insn::Lvrxl128 {
                vd: D7,
                ra: R3,
                rb: R4,
            },
            helper("lvrx", 100),
        ),
        (
            Insn::Stvlx {
                vs: D,
                ra: R3,
                rb: R4,
            },
            store("stvlx", 1),
        ),
        (
            Insn::Stvlxl {
                vs: D,
                ra: R3,
                rb: R4,
            },
            store("stvlx", 1),
        ),
        (
            Insn::Stvlx128 {
                vs: D7,
                ra: R3,
                rb: R4,
            },
            store("stvlx", 100),
        ),
        (
            Insn::Stvlxl128 {
                vs: D7,
                ra: R3,
                rb: R4,
            },
            store("stvlx", 100),
        ),
        (
            Insn::Stvrx {
                vs: D,
                ra: R3,
                rb: R4,
            },
            store("stvrx", 1),
        ),
        (
            Insn::Stvrxl {
                vs: D,
                ra: R3,
                rb: R4,
            },
            store("stvrx", 1),
        ),
        (
            Insn::Stvrx128 {
                vs: D7,
                ra: R3,
                rb: R4,
            },
            store("stvrx", 100),
        ),
        (
            Insn::Stvrxl128 {
                vs: D7,
                ra: R3,
                rb: R4,
            },
            store("stvrx", 100),
        ),
        (
            Insn::Lvsl {
                vd: D,
                ra: R3,
                rb: R4,
            },
            format!("ctx.v[1] = ops::lvsl({EA});"),
        ),
        (
            Insn::Lvsr {
                vd: D,
                ra: R3,
                rb: R4,
            },
            format!("ctx.v[1] = ops::lvsr({EA});"),
        ),
        (
            Insn::Lvsl128 {
                vd: D7,
                ra: R3,
                rb: R4,
            },
            format!("ctx.v[100] = ops::lvsl({EA});"),
        ),
        (
            Insn::Lvsr128 {
                vd: D7,
                ra: R3,
                rb: R4,
            },
            format!("ctx.v[100] = ops::lvsr({EA});"),
        ),
    ];
    for (insn, expected) in cases {
        assert_eq!(text(insn).unwrap(), expected, "{insn:?}");
    }
    // rA = 0 reads as zero, for the VMX128 forms too.
    assert_eq!(
        text(Insn::Lvx128 {
            vd: D,
            ra: R0,
            rb: R4
        })
        .unwrap(),
        "ctx.v[1] = mem.read_v128((ctx.r[4] as u32) & !0xf);"
    );
}

#[test]
fn stream_hints_emit_nothing() {
    check(cases! {
        Dst { t: false, ra: R3, rb: R4, strm: 1, ignored: 0 } => "";
        Dst { t: true, ra: R3, rb: R4, strm: 3, ignored: 0 } => "";
        Dstst { t: false, ra: R3, rb: R4, strm: 0, ignored: 0 } => "";
        Dstst { t: true, ra: R3, rb: R4, strm: 2, ignored: 0 } => "";
        Dss { all: false, strm: 1, ignored: 0 } => "";
        Dss { all: true, strm: 0, ignored: 0 } => "";
    });
}

#[test]
fn the_vscr_moves_go_through_ctx_vscr() {
    check(cases! {
        Mfvscr { vd: D } => "ctx.v[1] = ctx.vscr.mfvscr();";
        Mtvscr { vb: B } => "ctx.vscr.mtvscr(ctx.v[3]);";
    });
}

#[test]
fn integer_instructions_call_their_helpers() {
    check(cases! {
        Vaddubm { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vaddubm(ctx.v[2], ctx.v[3]);";
        Vadduhm { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vadduhm(ctx.v[2], ctx.v[3]);";
        Vadduwm { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vadduwm(ctx.v[2], ctx.v[3]);";
        Vsububm { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsububm(ctx.v[2], ctx.v[3]);";
        Vsubuhm { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsubuhm(ctx.v[2], ctx.v[3]);";
        Vsubuwm { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsubuwm(ctx.v[2], ctx.v[3]);";
        Vaddcuw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vaddcuw(ctx.v[2], ctx.v[3]);";
        Vsubcuw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsubcuw(ctx.v[2], ctx.v[3]);";
        Vavgub { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vavgub(ctx.v[2], ctx.v[3]);";
        Vavguh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vavguh(ctx.v[2], ctx.v[3]);";
        Vavguw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vavguw(ctx.v[2], ctx.v[3]);";
        Vavgsb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vavgsb(ctx.v[2], ctx.v[3]);";
        Vavgsh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vavgsh(ctx.v[2], ctx.v[3]);";
        Vavgsw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vavgsw(ctx.v[2], ctx.v[3]);";
        Vmaxub { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmaxub(ctx.v[2], ctx.v[3]);";
        Vmaxuh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmaxuh(ctx.v[2], ctx.v[3]);";
        Vmaxuw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmaxuw(ctx.v[2], ctx.v[3]);";
        Vmaxsb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmaxsb(ctx.v[2], ctx.v[3]);";
        Vmaxsh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmaxsh(ctx.v[2], ctx.v[3]);";
        Vmaxsw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmaxsw(ctx.v[2], ctx.v[3]);";
        Vminub { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vminub(ctx.v[2], ctx.v[3]);";
        Vminuh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vminuh(ctx.v[2], ctx.v[3]);";
        Vminuw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vminuw(ctx.v[2], ctx.v[3]);";
        Vminsb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vminsb(ctx.v[2], ctx.v[3]);";
        Vminsh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vminsh(ctx.v[2], ctx.v[3]);";
        Vminsw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vminsw(ctx.v[2], ctx.v[3]);";
        Vmuleub { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmuleub(ctx.v[2], ctx.v[3]);";
        Vmuleuh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmuleuh(ctx.v[2], ctx.v[3]);";
        Vmulesb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmulesb(ctx.v[2], ctx.v[3]);";
        Vmulesh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmulesh(ctx.v[2], ctx.v[3]);";
        Vmuloub { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmuloub(ctx.v[2], ctx.v[3]);";
        Vmulouh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmulouh(ctx.v[2], ctx.v[3]);";
        Vmulosb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmulosb(ctx.v[2], ctx.v[3]);";
        Vmulosh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmulosh(ctx.v[2], ctx.v[3]);";
        Vand { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vand(ctx.v[2], ctx.v[3]);";
        Vandc { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vandc(ctx.v[2], ctx.v[3]);";
        Vor { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vor(ctx.v[2], ctx.v[3]);";
        Vxor { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vxor(ctx.v[2], ctx.v[3]);";
        Vnor { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vnor(ctx.v[2], ctx.v[3]);";
        Vrlb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vrlb(ctx.v[2], ctx.v[3]);";
        Vrlh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vrlh(ctx.v[2], ctx.v[3]);";
        Vrlw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vrlw(ctx.v[2], ctx.v[3]);";
        Vslb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vslb(ctx.v[2], ctx.v[3]);";
        Vslh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vslh(ctx.v[2], ctx.v[3]);";
        Vslw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vslw(ctx.v[2], ctx.v[3]);";
        Vsrb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsrb(ctx.v[2], ctx.v[3]);";
        Vsrh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsrh(ctx.v[2], ctx.v[3]);";
        Vsrw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsrw(ctx.v[2], ctx.v[3]);";
        Vsrab { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsrab(ctx.v[2], ctx.v[3]);";
        Vsrah { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsrah(ctx.v[2], ctx.v[3]);";
        Vsraw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsraw(ctx.v[2], ctx.v[3]);";
        Vsl { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsl(ctx.v[2], ctx.v[3]);";
        Vsr { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsr(ctx.v[2], ctx.v[3]);";
        Vslo { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vslo(ctx.v[2], ctx.v[3]);";
        Vsro { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsro(ctx.v[2], ctx.v[3]);";
        Vmrghb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmrghb(ctx.v[2], ctx.v[3]);";
        Vmrghh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmrghh(ctx.v[2], ctx.v[3]);";
        Vmrghw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmrghw(ctx.v[2], ctx.v[3]);";
        Vmrglb { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmrglb(ctx.v[2], ctx.v[3]);";
        Vmrglh { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmrglh(ctx.v[2], ctx.v[3]);";
        Vmrglw { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmrglw(ctx.v[2], ctx.v[3]);";
        Vpkuhum { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vpkuhum(ctx.v[2], ctx.v[3]);";
        Vpkuwum { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vpkuwum(ctx.v[2], ctx.v[3]);";
        Vpkpx { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vpkpx(ctx.v[2], ctx.v[3]);";
        Vupkhsb { vd: D, vb: B } => "ctx.v[1] = ops::vupkhsb(ctx.v[3]);";
        Vupklsb { vd: D, vb: B } => "ctx.v[1] = ops::vupklsb(ctx.v[3]);";
        Vupkhsh { vd: D, vb: B } => "ctx.v[1] = ops::vupkhsh(ctx.v[3]);";
        Vupklsh { vd: D, vb: B } => "ctx.v[1] = ops::vupklsh(ctx.v[3]);";
        Vupkhpx { vd: D, vb: B } => "ctx.v[1] = ops::vupkhpx(ctx.v[3]);";
        Vupklpx { vd: D, vb: B } => "ctx.v[1] = ops::vupklpx(ctx.v[3]);";
        Vmladduhm { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vmladduhm(ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vmsumubm { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vmsumubm(ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vmsummbm { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vmsummbm(ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vmsumuhm { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vmsumuhm(ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vmsumshm { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vmsumshm(ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vsel { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vsel(ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vperm { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vperm(ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vsldoi { vd: D, va: A, vb: B, shb: 5 } => "ctx.v[1] = ops::vsldoi(ctx.v[2], ctx.v[3], 5);";
    });
}

#[test]
fn saturating_instructions_pass_the_vscr_mutably() {
    check(cases! {
        Vaddubs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vaddubs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vaddsbs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vaddsbs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vadduhs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vadduhs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vaddshs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vaddshs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vadduws { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vadduws(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vaddsws { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vaddsws(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsububs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsububs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsubsbs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsubsbs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsubuhs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsubuhs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsubshs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsubshs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsubuws { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsubuws(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsubsws { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsubsws(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsumsws { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsumsws(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsum2sws { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsum2sws(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsum4ubs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsum4ubs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsum4sbs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsum4sbs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsum4shs { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsum4shs(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vpkuhus { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vpkuhus(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vpkuwus { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vpkuwus(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vpkshus { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vpkshus(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vpkswus { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vpkswus(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vpkshss { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vpkshss(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vpkswss { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vpkswss(&mut ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vmhaddshs { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vmhaddshs(&mut ctx.vscr, ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vmhraddshs { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vmhraddshs(&mut ctx.vscr, ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vmsumuhs { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vmsumuhs(&mut ctx.vscr, ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vmsumshs { vd: D, va: A, vb: B, vc: C } => "ctx.v[1] = ops::vmsumshs(&mut ctx.vscr, ctx.v[2], ctx.v[3], ctx.v[4]);";
        Vctsxs { vd: D, vb: B, uim: 31 } => "ctx.v[1] = ops::vctsxs(&mut ctx.vscr, ctx.v[3], 31);";
        Vctuxs { vd: D, vb: B, uim: 0 } => "ctx.v[1] = ops::vctuxs(&mut ctx.vscr, ctx.v[3], 0);";
    });
}

#[test]
fn floating_point_instructions_read_the_vscr() {
    check(cases! {
        Vaddfp { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vaddfp(ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vsubfp { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vsubfp(ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vmaxfp { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vmaxfp(ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vminfp { vd: D, va: A, vb: B } => "ctx.v[1] = ops::vminfp(ctx.vscr, ctx.v[2], ctx.v[3]);";
        Vrefp { vd: D, vb: B } => "ctx.v[1] = ops::vrefp(ctx.vscr, ctx.v[3]);";
        Vrsqrtefp { vd: D, vb: B } => "ctx.v[1] = ops::vrsqrtefp(ctx.vscr, ctx.v[3]);";
        Vexptefp { vd: D, vb: B } => "ctx.v[1] = ops::vexptefp(ctx.vscr, ctx.v[3]);";
        Vlogefp { vd: D, vb: B } => "ctx.v[1] = ops::vlogefp(ctx.vscr, ctx.v[3]);";
        Vrfin { vd: D, vb: B } => "ctx.v[1] = ops::vrfin(ctx.vscr, ctx.v[3]);";
        Vrfiz { vd: D, vb: B } => "ctx.v[1] = ops::vrfiz(ctx.vscr, ctx.v[3]);";
        Vrfip { vd: D, vb: B } => "ctx.v[1] = ops::vrfip(ctx.vscr, ctx.v[3]);";
        Vrfim { vd: D, vb: B } => "ctx.v[1] = ops::vrfim(ctx.vscr, ctx.v[3]);";
        // vmaddfp vD, vA, vC, vB: the helper takes vA, vC, vB.
        Vmaddfp { vd: D, va: A, vc: C, vb: B } => "ctx.v[1] = ops::vmaddfp(ctx.vscr, ctx.v[2], ctx.v[4], ctx.v[3]);";
        Vnmsubfp { vd: D, va: A, vc: C, vb: B } => "ctx.v[1] = ops::vnmsubfp(ctx.vscr, ctx.v[2], ctx.v[4], ctx.v[3]);";
        Vcfsx { vd: D, vb: B, uim: 10 } => "ctx.v[1] = ops::vcfsx(ctx.v[3], 10);";
        Vcfux { vd: D, vb: B, uim: 1 } => "ctx.v[1] = ops::vcfux(ctx.v[3], 1);";
    });
}

#[test]
fn splats_pass_their_immediates() {
    check(cases! {
        Vspltb { vd: D, vb: B, uim: 15 } => "ctx.v[1] = ops::vspltb(ctx.v[3], 15);";
        Vsplth { vd: D, vb: B, uim: 7 } => "ctx.v[1] = ops::vsplth(ctx.v[3], 7);";
        Vspltw { vd: D, vb: B, uim: 3 } => "ctx.v[1] = ops::vspltw(ctx.v[3], 3);";
        Vspltisb { vd: D, sim: -16 } => "ctx.v[1] = ops::vspltisb(-16);";
        Vspltish { vd: D, sim: 15 } => "ctx.v[1] = ops::vspltish(15);";
        Vspltisw { vd: D, sim: -1 } => "ctx.v[1] = ops::vspltisw(-1);";
    });
}

#[test]
fn compares_with_rc_set_cr6() {
    let record = |name: &str, vscr: &str| {
        format!(
            "ctx.v[1] = ops::{name}({vscr}ctx.v[2], ctx.v[3]);\nctx.cr.set_field(6, ops::vcmp_cr6(ctx.v[1]));"
        )
    };
    for (name, insn, dot) in [
        (
            "vcmpequb",
            Insn::Vcmpequb {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpequb {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpequh",
            Insn::Vcmpequh {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpequh {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpequw",
            Insn::Vcmpequw {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpequw {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgtub",
            Insn::Vcmpgtub {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgtub {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgtuh",
            Insn::Vcmpgtuh {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgtuh {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgtuw",
            Insn::Vcmpgtuw {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgtuw {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgtsb",
            Insn::Vcmpgtsb {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgtsb {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgtsh",
            Insn::Vcmpgtsh {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgtsh {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgtsw",
            Insn::Vcmpgtsw {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgtsw {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
    ] {
        let plain = format!("ctx.v[1] = ops::{name}(ctx.v[2], ctx.v[3]);");
        assert_eq!(text(insn).unwrap(), plain);
        assert_eq!(text(dot).unwrap(), record(name, ""));
    }
    for (name, insn, dot) in [
        (
            "vcmpeqfp",
            Insn::Vcmpeqfp {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpeqfp {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgefp",
            Insn::Vcmpgefp {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgefp {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgtfp",
            Insn::Vcmpgtfp {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgtfp {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpeqfp",
            Insn::Vcmpeqfp128 {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpeqfp128 {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgefp",
            Insn::Vcmpgefp128 {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgefp128 {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
        (
            "vcmpgtfp",
            Insn::Vcmpgtfp128 {
                vd: D,
                va: A,
                vb: B,
                rc: false,
            },
            Insn::Vcmpgtfp128 {
                vd: D,
                va: A,
                vb: B,
                rc: true,
            },
        ),
    ] {
        let plain = format!("ctx.v[1] = ops::{name}(ctx.vscr, ctx.v[2], ctx.v[3]);");
        assert_eq!(text(insn).unwrap(), plain);
        assert_eq!(text(dot).unwrap(), record(name, "ctx.vscr, "));
    }
    assert_eq!(
        text(Insn::Vcmpequw128 {
            vd: D7,
            va: A7,
            vb: B7,
            rc: true
        })
        .unwrap(),
        "ctx.v[100] = ops::vcmpequw(ctx.v[64], ctx.v[127]);\nctx.cr.set_field(6, ops::vcmp_cr6(ctx.v[100]));"
    );
    // vcmpbfp. reports only whether every element is in bounds.
    let bounds = "ctx.v[1] = ops::vcmpbfp(ctx.vscr, ctx.v[2], ctx.v[3]);";
    assert_eq!(
        text(Insn::Vcmpbfp {
            vd: D,
            va: A,
            vb: B,
            rc: false
        })
        .unwrap(),
        bounds
    );
    for dot in [
        Insn::Vcmpbfp {
            vd: D,
            va: A,
            vb: B,
            rc: true,
        },
        Insn::Vcmpbfp128 {
            vd: D,
            va: A,
            vb: B,
            rc: true,
        },
    ] {
        assert_eq!(
            text(dot).unwrap(),
            format!("{bounds}\nctx.cr.set_field(6, ops::vcmpbfp_cr6(ctx.v[1]));")
        );
    }
}

#[test]
fn vmx128_forms_reach_registers_above_31() {
    check(cases! {
        Vaddfp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vaddfp(ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vsubfp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vsubfp(ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vmulfp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vmulfp128(ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vmaxfp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vmaxfp(ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vminfp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vminfp(ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vmsum3fp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vmsum3fp128(ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vmsum4fp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vmsum4fp128(ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vrefp128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vrefp(ctx.vscr, ctx.v[127]);";
        Vrsqrtefp128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vrsqrtefp(ctx.vscr, ctx.v[127]);";
        Vexptefp128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vexptefp(ctx.vscr, ctx.v[127]);";
        Vlogefp128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vlogefp(ctx.vscr, ctx.v[127]);";
        Vrfin128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vrfin(ctx.vscr, ctx.v[127]);";
        Vrfiz128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vrfiz(ctx.vscr, ctx.v[127]);";
        Vrfip128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vrfip(ctx.vscr, ctx.v[127]);";
        Vrfim128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vrfim(ctx.vscr, ctx.v[127]);";
        Vand128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vand(ctx.v[64], ctx.v[127]);";
        Vandc128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vandc(ctx.v[64], ctx.v[127]);";
        Vor128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vor(ctx.v[64], ctx.v[127]);";
        Vxor128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vxor(ctx.v[64], ctx.v[127]);";
        Vnor128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vnor(ctx.v[64], ctx.v[127]);";
        Vslo128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vslo(ctx.v[64], ctx.v[127]);";
        Vsro128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vsro(ctx.v[64], ctx.v[127]);";
        Vrlw128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vrlw(ctx.v[64], ctx.v[127]);";
        Vslw128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vslw(ctx.v[64], ctx.v[127]);";
        Vsraw128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vsraw(ctx.v[64], ctx.v[127]);";
        Vsrw128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vsrw(ctx.v[64], ctx.v[127]);";
        Vmrghw128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vmrghw(ctx.v[64], ctx.v[127]);";
        Vmrglw128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vmrglw(ctx.v[64], ctx.v[127]);";
        Vpkuhum128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vpkuhum(ctx.v[64], ctx.v[127]);";
        Vpkuwum128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vpkuwum(ctx.v[64], ctx.v[127]);";
        Vpkuhus128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vpkuhus(&mut ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vpkuwus128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vpkuwus(&mut ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vpkshus128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vpkshus(&mut ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vpkswus128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vpkswus(&mut ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vpkshss128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vpkshss(&mut ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vpkswss128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vpkswss(&mut ctx.vscr, ctx.v[64], ctx.v[127]);";
        Vsldoi128 { vd: D7, va: A7, vb: B7, sh: 12 } => "ctx.v[100] = ops::vsldoi(ctx.v[64], ctx.v[127], 12);";
        Vperm128 { vd: D7, va: A7, vb: B7, vc: Vr(7) } => "ctx.v[100] = ops::vperm(ctx.v[64], ctx.v[127], ctx.v[7]);";
        Vspltw128 { vd: D7, vb: B7, uimm: 2 } => "ctx.v[100] = ops::vspltw(ctx.v[127], 2);";
        Vspltisw128 { vd: D7, vb: B7, simm: -16 } => "ctx.v[100] = ops::vspltisw(-16);";
        Vpermwi128 { vd: D7, vb: B7, perm: 0xE4 } => "ctx.v[100] = ops::vpermwi128(ctx.v[127], 228);";
        Vrlimi128 { vd: D7, vb: B7, imm: 0xF, z: 1 } => "ctx.v[100] = ops::vrlimi128(ctx.v[100], ctx.v[127], 15, 1);";
    });
}

#[test]
fn vmx128_forms_that_read_vd_pass_it_in_its_role() {
    check(cases! {
        // vmaddfp128 vD, vA, vB is vA × vB + vD; vmaddcfp128 is vA × vD + vB.
        Vmaddfp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vmaddfp(ctx.vscr, ctx.v[64], ctx.v[127], ctx.v[100]);";
        Vmaddcfp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vmaddfp(ctx.vscr, ctx.v[64], ctx.v[100], ctx.v[127]);";
        Vnmsubfp128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vnmsubfp(ctx.vscr, ctx.v[64], ctx.v[127], ctx.v[100]);";
        Vsel128 { vd: D7, va: A7, vb: B7 } => "ctx.v[100] = ops::vsel(ctx.v[64], ctx.v[127], ctx.v[100]);";
    });
}

#[test]
fn vmx128_conversions_take_the_raw_five_bit_scale() {
    check(cases! {
        // -1 in a 5-bit field is 31.
        Vcfpsxws128 { vd: D7, vb: B7, simm: -1 } => "ctx.v[100] = ops::vctsxs(&mut ctx.vscr, ctx.v[127], 31);";
        Vcfpsxws128 { vd: D7, vb: B7, simm: 3 } => "ctx.v[100] = ops::vctsxs(&mut ctx.vscr, ctx.v[127], 3);";
        Vcfpuxws128 { vd: D7, vb: B7, uimm: 31 } => "ctx.v[100] = ops::vctuxs(&mut ctx.vscr, ctx.v[127], 31);";
        Vcsxwfp128 { vd: D7, vb: B7, simm: -16 } => "ctx.v[100] = ops::vcfsx(ctx.v[127], 16);";
        Vcuxwfp128 { vd: D7, vb: B7, uimm: 5 } => "ctx.v[100] = ops::vcfux(ctx.v[127], 5);";
    });
}

#[test]
fn vmx128_unpacks_read_the_hidden_va_field() {
    check(cases! {
        Vupkhsb128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vupkhsb(ctx.v[127]);";
        Vupklsb128 { vd: D7, vb: B7, ignored: 0 } => "ctx.v[100] = ops::vupklsb(ctx.v[127]);";
        Vupkhsb128 { vd: D7, vb: B7, ignored: 0x60 } => "ctx.v[100] = ops::vupkhsh(ctx.v[127]);";
        Vupklsb128 { vd: D7, vb: B7, ignored: 0x60 } => "ctx.v[100] = ops::vupklsh(ctx.v[127]);";
    });
}

#[test]
fn d3d_packs_split_their_fields_and_reject_the_unknown_ones() {
    check(cases! {
        // IMM = type << 2 | mask, z = shift.
        Vpkd3d128 { vd: D7, vb: B7, imm: 0b10010, z: 3 } => "ctx.v[100] = ops::vpkd3d128(ctx.v[100], ctx.v[127], 4, 2, 3);";
        Vupkd3d128 { vd: D7, vb: B7, uimm: 0b10100 } => "ctx.v[100] = ops::vupkd3d128(ctx.v[127], 5);";
    });
    let missing = |insn: Insn| match text(insn) {
        Err(Error::MissingEmit { counts }) => counts.into_keys().collect::<Vec<_>>(),
        other => panic!("{insn:?}: {other:?}"),
    };
    assert_eq!(
        missing(Insn::Vpkd3d128 {
            vd: D,
            vb: B,
            imm: 0b11001,
            z: 0
        }),
        ["vpkd3d128 (type 6)"]
    );
    assert_eq!(
        missing(Insn::Vpkd3d128 {
            vd: D,
            vb: B,
            imm: 0b00100,
            z: 0
        }),
        ["vpkd3d128 (mask 0)"]
    );
    assert_eq!(
        missing(Insn::Vupkd3d128 {
            vd: D,
            vb: B,
            uimm: 0b11100
        }),
        ["vupkd3d128 (type 7)"]
    );
}

#[test]
fn mfocrf_reads_one_field_in_place() {
    assert_eq!(
        text(Insn::Mfocrf { rt: R3, fxm: 0x02 }).unwrap(),
        "ctx.r[3] = u64::from(ctx.cr.field(6)) << 4;"
    );
    assert_eq!(
        text(Insn::Mfocrf { rt: R3, fxm: 0x80 }).unwrap(),
        "ctx.r[3] = u64::from(ctx.cr.field(0)) << 28;"
    );
}

/// Whether a row of the decoder is a VMX or VMX128 instruction.
fn is_vector(form: Form, mnemonic: &str) -> bool {
    let vector_form = matches!(
        form,
        Form::VA
            | Form::VX
            | Form::VXR
            | Form::VX128
            | Form::VX128_1
            | Form::VX128_2
            | Form::VX128_3
            | Form::VX128_4
            | Form::VX128_5
            | Form::VX128_R
            | Form::VX128_P
    );
    let vector_x = [
        "lvsl", "lvsr", "lvebx", "lvehx", "lvewx", "lvx", "lvxl", "stvebx", "stvehx", "stvewx",
        "stvx", "stvxl", "dst", "dstst", "dss", "lvlx", "lvrx", "lvlxl", "lvrxl", "stvlx", "stvrx",
        "stvlxl", "stvrxl",
    ];
    vector_form || vector_x.contains(&mnemonic)
}

/// Every vector row of the decoder has an `emit_*`. A row is tried with its fields at zero, so
/// `vpkd3d128` comes out with mask 0, which is the one opcode it may report as missing.
#[test]
fn every_vector_row_has_an_emitter() {
    let mut rows = 0;
    let mut missing = BTreeMap::new();
    for info in OPCODES
        .iter()
        .filter(|info| is_vector(info.form, info.mnemonic))
    {
        rows += 1;
        let insn =
            decode(info.value).unwrap_or_else(|| panic!("{} with zero fields", info.mnemonic));
        if let Err(Error::MissingEmit { counts }) = text(insn) {
            missing.extend(counts);
        }
    }
    assert_eq!(rows, 242, "the VMX and VMX128 rows");
    assert_eq!(
        missing,
        BTreeMap::from([("vpkd3d128 (mask 0)".to_owned(), 1)])
    );
}
