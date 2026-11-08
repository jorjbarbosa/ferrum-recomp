// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Integer arithmetic, logic, comparisons and traps.
//!
//! Results keep all 64 bits; CR0, CA and OV follow 32-bit mode. The forms with OE=1 set OV, which
//! no test covers, so they are reported as opcodes without `emit_*` (`addo` and so on) until one
//! does.

use ferrum_decoder::{CrField, Gpr, Insn};

use super::{Emitter, imm, plus, r, w};
use crate::error::Error;

/// Emits `insn` if it belongs to this family, and returns whether it did.
pub(super) fn emit(e: &mut Emitter<'_>, at: u32, insn: &Insn) -> Result<bool, Error> {
    match *insn {
        Insn::Addi { rt, ra, si } => e.set(rt, plus_or_zero(ra, i64::from(si))),
        Insn::Addis { rt, ra, si } => e.set(rt, plus_or_zero(ra, i64::from(si) << 16)),
        Insn::Add { rt, ra, rb, oe, rc } => {
            let value = format!("{}.wrapping_add({})", r(ra), r(rb));
            xo(e, "add", oe, rt, rc, value);
        }
        Insn::Subf { rt, ra, rb, oe, rc } => {
            let value = format!("{}.wrapping_sub({})", r(rb), r(ra));
            xo(e, "subf", oe, rt, rc, value);
        }
        Insn::Neg { rt, ra, oe, rc } => {
            xo(e, "neg", oe, rt, rc, format!("{}.wrapping_neg()", r(ra)));
        }
        Insn::Mulli { rt, ra, si } => {
            e.set(rt, format!("({} as i64).wrapping_mul({si}) as u64", r(ra)));
        }
        Insn::Mullw { rt, ra, rb, oe, rc } => {
            let value = format!(
                "i64::from({} as i32).wrapping_mul(i64::from({} as i32)) as u64",
                r(ra),
                r(rb)
            );
            xo(e, "mullw", oe, rt, rc, value);
        }
        Insn::Mulld { rt, ra, rb, oe, rc } => {
            let value = format!("{}.wrapping_mul({})", r(ra), r(rb));
            xo(e, "mulld", oe, rt, rc, value);
        }
        _ => {
            return Ok(carrying(e, insn)
                || high_and_divide(e, insn)
                || logic(e, insn)
                || compare(e, at, insn));
        }
    }
    Ok(true)
}

/// `rA|0 + value`: register 0 reads as zero in `addi` and `addis`.
fn plus_or_zero(ra: Gpr, value: i64) -> String {
    if ra.0 == 0 {
        imm(value)
    } else {
        plus(&r(ra), value)
    }
}

/// An XO-form result, with CR0 if `rc`. With OE=1 the instruction is counted as missing.
fn xo(e: &mut Emitter<'_>, mnemonic: &str, oe: bool, rt: Gpr, rc: bool, value: String) {
    if oe {
        e.missing(format!("{mnemonic}o"));
    } else {
        e.set_rc(rt, value, rc);
    }
}

/// The additions and subtractions that set CA, each one call of `ops::add_with_carry`.
fn carrying(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let not = |ra: Gpr| format!("!{}", r(ra));
    let (mnemonic, rt, a, b, carry, oe, rc) = match *insn {
        Insn::Addic { rt, ra, si } => ("addic", rt, r(ra), imm(si.into()), "false", false, false),
        Insn::AddicDot { rt, ra, si } => {
            ("addic.", rt, r(ra), imm(si.into()), "false", false, true)
        }
        Insn::Subfic { rt, ra, si } => {
            ("subfic", rt, not(ra), imm(si.into()), "true", false, false)
        }
        Insn::Addc { rt, ra, rb, oe, rc } => ("addc", rt, r(ra), r(rb), "false", oe, rc),
        Insn::Adde { rt, ra, rb, oe, rc } => ("adde", rt, r(ra), r(rb), "ctx.xer.ca", oe, rc),
        Insn::Subfc { rt, ra, rb, oe, rc } => ("subfc", rt, not(ra), r(rb), "true", oe, rc),
        Insn::Subfe { rt, ra, rb, oe, rc } => ("subfe", rt, not(ra), r(rb), "ctx.xer.ca", oe, rc),
        Insn::Addme { rt, ra, oe, rc } => {
            ("addme", rt, r(ra), "u64::MAX".into(), "ctx.xer.ca", oe, rc)
        }
        Insn::Addze { rt, ra, oe, rc } => ("addze", rt, r(ra), "0".into(), "ctx.xer.ca", oe, rc),
        Insn::Subfme { rt, ra, oe, rc } => (
            "subfme",
            rt,
            not(ra),
            "u64::MAX".into(),
            "ctx.xer.ca",
            oe,
            rc,
        ),
        Insn::Subfze { rt, ra, oe, rc } => {
            ("subfze", rt, not(ra), "0".into(), "ctx.xer.ca", oe, rc)
        }
        _ => return false,
    };
    if oe {
        e.missing(format!("{mnemonic}o"));
        return true;
    }
    e.open("{");
    e.line(format!(
        "let (value, ca, _) = ops::add_with_carry({a}, {b}, {carry});"
    ));
    e.line(format!("ctx.r[{}] = value;", rt.0));
    e.line("ctx.xer.ca = ca;");
    if rc {
        e.record(rt);
    }
    e.close("}");
    true
}

/// The high halves of products, and divisions.
///
/// The ISA leaves the high word of `mulhw`, `mulhwu`, `divw` and `divwu` undefined, and the whole
/// result of a division by zero or one that overflows. The values here are those the suite
/// expects: `mulhw` sign-extends its word and `mulhwu` zero-extends it (`instr_mulhw`,
/// `instr_mulhwu`), a word quotient is zero-extended (`instr_divw`), a division by zero gives 0
/// (`instr_divdx`), and an overflowing one gives what `wrapping_div` does.
fn high_and_divide(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let (rt, rc, value) = match *insn {
        Insn::Mulhw { rt, ra, rb, rc } => (
            rt,
            rc,
            format!(
                "((i64::from({} as i32) * i64::from({} as i32)) >> 32) as u64",
                r(ra),
                r(rb)
            ),
        ),
        Insn::Mulhwu { rt, ra, rb, rc } => (
            rt,
            rc,
            format!("(u64::from({}) * u64::from({})) >> 32", w(ra), w(rb)),
        ),
        Insn::Mulhd { rt, ra, rb, rc } => (
            rt,
            rc,
            format!(
                "((i128::from({} as i64) * i128::from({} as i64)) >> 64) as u64",
                r(ra),
                r(rb)
            ),
        ),
        Insn::Mulhdu { rt, ra, rb, rc } => (
            rt,
            rc,
            format!(
                "((u128::from({}) * u128::from({})) >> 64) as u64",
                r(ra),
                r(rb)
            ),
        ),
        Insn::Divw { oe: true, .. } => return missing(e, "divwo"),
        Insn::Divw { rt, ra, rb, rc, .. } => (
            rt,
            rc,
            format!(
                "if {b} as i32 == 0 {{ 0 }} else {{ u64::from(({a} as i32).wrapping_div({b} as i32) as u32) }}",
                a = r(ra),
                b = r(rb)
            ),
        ),
        Insn::Divwu { oe: true, .. } => return missing(e, "divwuo"),
        Insn::Divwu { rt, ra, rb, rc, .. } => (
            rt,
            rc,
            format!(
                "if {b} == 0 {{ 0 }} else {{ u64::from({a} / {b}) }}",
                a = w(ra),
                b = w(rb)
            ),
        ),
        Insn::Divd { oe: true, .. } => return missing(e, "divdo"),
        Insn::Divd { rt, ra, rb, rc, .. } => (
            rt,
            rc,
            format!(
                "if {b} == 0 {{ 0 }} else {{ ({a} as i64).wrapping_div({b} as i64) as u64 }}",
                a = r(ra),
                b = r(rb)
            ),
        ),
        Insn::Divdu { oe: true, .. } => return missing(e, "divduo"),
        Insn::Divdu { rt, ra, rb, rc, .. } => (
            rt,
            rc,
            format!(
                "if {b} == 0 {{ 0 }} else {{ {a} / {b} }}",
                a = r(ra),
                b = r(rb)
            ),
        ),
        _ => return false,
    };
    e.set_rc(rt, value, rc);
    true
}

fn missing(e: &mut Emitter<'_>, name: &str) -> bool {
    e.missing(name);
    true
}

/// Logical operations, sign extensions and leading-zero counts.
fn logic(e: &mut Emitter<'_>, insn: &Insn) -> bool {
    let binary = |ra: Gpr, rs: Gpr, rb: Gpr, op: &str, rc: bool| -> (Gpr, String, bool) {
        let (s, b) = (r(rs), r(rb));
        let value = match op {
            "and" => format!("{s} & {b}"),
            "andc" => format!("{s} & !{b}"),
            "or" => format!("{s} | {b}"),
            "orc" => format!("{s} | !{b}"),
            "xor" => format!("{s} ^ {b}"),
            "nand" => format!("!({s} & {b})"),
            "nor" => format!("!({s} | {b})"),
            "eqv" => format!("!({s} ^ {b})"),
            _ => unreachable!("not a logical operation: {op}"),
        };
        (ra, value, rc)
    };
    let (ra, value, rc) = match *insn {
        Insn::And { ra, rs, rb, rc } => binary(ra, rs, rb, "and", rc),
        Insn::Andc { ra, rs, rb, rc } => binary(ra, rs, rb, "andc", rc),
        Insn::Or { ra, rs, rb, rc } => binary(ra, rs, rb, "or", rc),
        Insn::Orc { ra, rs, rb, rc } => binary(ra, rs, rb, "orc", rc),
        Insn::Xor { ra, rs, rb, rc } => binary(ra, rs, rb, "xor", rc),
        Insn::Nand { ra, rs, rb, rc } => binary(ra, rs, rb, "nand", rc),
        Insn::Nor { ra, rs, rb, rc } => binary(ra, rs, rb, "nor", rc),
        Insn::Eqv { ra, rs, rb, rc } => binary(ra, rs, rb, "eqv", rc),
        Insn::Ori { ra, rs, ui } => (ra, format!("{} | {ui:#x}", r(rs)), false),
        Insn::Oris { ra, rs, ui } => (ra, format!("{} | {:#x}", r(rs), u64::from(ui) << 16), false),
        Insn::Xori { ra, rs, ui } => (ra, format!("{} ^ {ui:#x}", r(rs)), false),
        Insn::Xoris { ra, rs, ui } => {
            (ra, format!("{} ^ {:#x}", r(rs), u64::from(ui) << 16), false)
        }
        Insn::AndiDot { ra, rs, ui } => (ra, format!("{} & {ui:#x}", r(rs)), true),
        Insn::AndisDot { ra, rs, ui } => {
            (ra, format!("{} & {:#x}", r(rs), u64::from(ui) << 16), true)
        }
        Insn::Extsb { ra, rs, rc } => (ra, format!("{} as i8 as i64 as u64", r(rs)), rc),
        Insn::Extsh { ra, rs, rc } => (ra, format!("{} as i16 as i64 as u64", r(rs)), rc),
        Insn::Extsw { ra, rs, rc } => (ra, format!("{} as i32 as i64 as u64", r(rs)), rc),
        Insn::Cntlzw { ra, rs, rc } => (ra, format!("u64::from({}.leading_zeros())", w(rs)), rc),
        Insn::Cntlzd { ra, rs, rc } => (ra, format!("u64::from({}.leading_zeros())", r(rs)), rc),
        _ => return false,
    };
    e.set_rc(ra, value, rc);
    true
}

/// Comparisons, and traps, which compare too.
fn compare(e: &mut Emitter<'_>, at: u32, insn: &Insn) -> bool {
    let set = |e: &mut Emitter<'_>, bf: CrField, a: String, b: String| {
        e.line(format!(
            "ctx.cr.set_compare({}, {a}, {b}, ctx.xer.so);",
            bf.0
        ));
    };
    match *insn {
        Insn::Cmp {
            bf,
            l: true,
            ra,
            rb,
        } => set(
            e,
            bf,
            format!("{} as i64", r(ra)),
            format!("{} as i64", r(rb)),
        ),
        Insn::Cmp {
            bf,
            l: false,
            ra,
            rb,
        } => set(
            e,
            bf,
            format!("{} as i32", r(ra)),
            format!("{} as i32", r(rb)),
        ),
        Insn::Cmpl {
            bf,
            l: true,
            ra,
            rb,
        } => set(e, bf, r(ra), r(rb)),
        Insn::Cmpl {
            bf,
            l: false,
            ra,
            rb,
        } => set(e, bf, w(ra), w(rb)),
        Insn::Cmpi {
            bf,
            l: true,
            ra,
            si,
            ..
        } => set(e, bf, format!("{} as i64", r(ra)), format!("{si}i64")),
        Insn::Cmpi {
            bf,
            l: false,
            ra,
            si,
            ..
        } => set(e, bf, format!("{} as i32", r(ra)), format!("{si}i32")),
        Insn::Cmpli {
            bf,
            l: true,
            ra,
            ui,
            ..
        } => set(e, bf, r(ra), format!("{ui:#x}u64")),
        Insn::Cmpli {
            bf,
            l: false,
            ra,
            ui,
            ..
        } => set(e, bf, w(ra), format!("{ui:#x}u32")),
        Insn::Tw { to, ra, rb } => trap(e, at, to, Width::Word, r(ra), r(rb)),
        Insn::Td { to, ra, rb } => trap(e, at, to, Width::Double, r(ra), r(rb)),
        Insn::Twi { to, ra, si } => {
            trap(e, at, to, Width::Word, r(ra), format!("({si}i64 as u64)"))
        }
        Insn::Tdi { to, ra, si } => {
            trap(e, at, to, Width::Double, r(ra), format!("({si}i64 as u64)"))
        }
        _ => return false,
    }
    true
}

/// The operand width of a trap.
#[derive(Clone, Copy)]
enum Width {
    Word,
    Double,
}

/// A trap: panics if any comparison that TO selects holds between `a` and `b`, two 64-bit
/// expressions of which a word trap compares the low words.
fn trap(e: &mut Emitter<'_>, at: u32, to: u8, width: Width, a: String, b: String) {
    if e.program.trap_as_nop() {
        return;
    }
    let (signed, unsigned) = match width {
        Width::Word => ("i32", "u32"),
        Width::Double => ("i64", "u64"),
    };
    let s = |x: &str| format!("({x} as {signed})");
    let u = |x: &str| format!("({x} as {unsigned})");
    let tests = [
        (0x10, format!("{} < {}", s(&a), s(&b))),
        (0x08, format!("{} > {}", s(&a), s(&b))),
        (0x04, format!("{} == {}", u(&a), u(&b))),
        (0x02, format!("{} < {}", u(&a), u(&b))),
        (0x01, format!("{} > {}", u(&a), u(&b))),
    ];
    let terms: Vec<String> = tests
        .into_iter()
        .filter(|&(bit, _)| to & bit != 0)
        .map(|(_, test)| test)
        .collect();
    if !terms.is_empty() {
        e.line(format!(
            "if {} {{ ops::trap({at:#010x}); }}",
            terms.join(" || ")
        ));
    }
}
