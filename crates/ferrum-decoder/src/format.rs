// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Prints instructions the way `objdump -Mpower7 -Mvmx128` does.
//!
//! Most instructions print from their row of the opcode table. The rest are simplified mnemonics,
//! which [`simplified`] picks by looking at the operands, as with `li` for `addi` from `r0`.
//!
//! objdump pads the mnemonic to 7 columns and adds a space whenever the instruction can take
//! operands, even if it prints none. That is why `sync` comes out with trailing spaces.

use std::fmt::Write;

use crate::fields::{CrBit, CrField, Field, Fpr, Gpr, Print, Vr};
use crate::spr;
use crate::table::{Insn, OpcodeInfo};

/// One operand as it appears in the text.
#[derive(Debug, Clone, Copy)]
enum Arg {
    /// `r3`.
    R(Gpr),
    /// `r3`, or `0` for register 0.
    R0(Gpr),
    /// `f3`.
    F(Fpr),
    /// `v3`.
    V(Vr),
    /// `cr3`.
    Cr(CrField),
    /// `4*cr3+eq`.
    Bit(CrBit),
    /// A decimal number.
    Int(i32),
    /// `16(`, with the next operand as the base register.
    Disp(i32),
    /// A branch target given as an offset from the instruction.
    Relative(i32),
    /// A branch target given as an address.
    Absolute(u32),
}

/// Formats an instruction without knowing its address.
///
/// A relative branch target has no absolute value here, so it prints as an offset from the
/// instruction, as in `b       .+0x10`. Use [`format_at`] to get what objdump prints.
pub fn format(insn: &Insn) -> String {
    render(insn, None)
}

/// Formats an instruction that lives at `address`, with its branch target as an address.
pub fn format_at(insn: &Insn, address: u32) -> String {
    render(insn, Some(address))
}

/// Formats a word that [`decode`](crate::decode) has no instruction for, the way objdump does.
pub fn format_undecoded(word: u32) -> String {
    format!(".long {word:#x}")
}

fn render(insn: &Insn, address: Option<u32>) -> String {
    let word = insn.encode();
    simplified(insn, address).unwrap_or_else(|| from_table(insn.opcode().info(), word, address))
}

/// Writes operands, with the commas and parentheses between them.
struct Operands<'a> {
    out: &'a mut String,
    address: Option<u32>,
    first: bool,
    open_paren: bool,
}

impl Operands<'_> {
    fn write(&mut self, arg: Arg) {
        if !self.first && !self.open_paren {
            self.out.push(',');
        }
        self.first = false;
        let close = self.open_paren;
        self.open_paren = false;
        // Writing to a String cannot fail.
        let _ = match arg {
            Arg::R(Gpr(n)) => write!(self.out, "r{n}"),
            Arg::R0(Gpr(0)) => write!(self.out, "0"),
            Arg::R0(Gpr(n)) => write!(self.out, "r{n}"),
            Arg::F(Fpr(n)) => write!(self.out, "f{n}"),
            Arg::V(Vr(n)) => write!(self.out, "v{n}"),
            Arg::Cr(CrField(n)) => write!(self.out, "cr{n}"),
            Arg::Bit(bit) => write_cr_bit(self.out, bit),
            Arg::Int(n) => write!(self.out, "{n}"),
            Arg::Disp(n) => {
                self.open_paren = true;
                write!(self.out, "{n}(")
            }
            Arg::Relative(offset) => match self.address {
                Some(address) => write!(self.out, "{:#x}", address.wrapping_add_signed(offset)),
                None if offset < 0 => write!(self.out, ".-{:#x}", offset.unsigned_abs()),
                None => write!(self.out, ".+{offset:#x}"),
            },
            Arg::Absolute(target) => write!(self.out, "{target:#x}"),
        };
        if close {
            self.out.push(')');
        }
    }
}

fn write_cr_bit(out: &mut String, CrBit(bit): CrBit) -> std::fmt::Result {
    const NAMES: [&str; 4] = ["lt", "gt", "eq", "so"];
    let cr = bit >> 2;
    if cr != 0 {
        write!(out, "4*cr{cr}+")?;
    }
    out.write_str(NAMES[usize::from(bit & 3)])
}

/// The start of a line: the mnemonic, padded because the instruction takes operands.
fn padded_name(name: &str) -> String {
    format!("{name:<7} ")
}

/// A line with these operands, padded as an instruction with operands is.
fn line(name: &str, args: &[Arg], address: Option<u32>) -> String {
    let mut out = padded_name(name);
    let mut operands = Operands {
        out: &mut out,
        address,
        first: true,
        open_paren: false,
    };
    for &arg in args {
        operands.write(arg);
    }
    out
}

/// A line for an instruction that never takes operands, so it has no padding.
fn bare(name: &str) -> String {
    name.to_owned()
}

/// The suffix of a mnemonic, from the fields that add one.
fn with_suffixes(row: &OpcodeInfo, word: u32) -> String {
    let set = |print| {
        row.fields
            .iter()
            .any(|f| f.print == print && f.get(word) != 0)
    };
    let mut name = row.mnemonic.to_owned();
    for (print, suffix) in [
        (Print::SuffixOe, "o"),
        (Print::SuffixLk, "l"),
        (Print::SuffixAa, "a"),
        (Print::SuffixRc, "."),
    ] {
        if set(print) {
            name.push_str(suffix);
        }
    }
    name
}

/// The operand of a field, if it prints as one.
fn arg_of(field: &Field, word: u32) -> Option<Arg> {
    let value = field.get(word);
    // The narrowing casts below are safe because register fields are at most 7 bits wide.
    Some(match field.print {
        Print::Gpr => Arg::R(Gpr(value as u8)),
        Print::GprOrZero => Arg::R0(Gpr(value as u8)),
        Print::Fpr => Arg::F(Fpr(value as u8)),
        Print::Vr => Arg::V(Vr(value as u8)),
        Print::Cr => Arg::Cr(CrField(value as u8)),
        Print::CrBit => Arg::Bit(CrBit(value as u8)),
        Print::Int | Print::Optional => Arg::Int(value),
        Print::Disp => Arg::Disp(value),
        Print::Relative => Arg::Relative(value),
        Print::ByteCount => Arg::Int(if value == 0 { 32 } else { value }),
        Print::Hidden
        | Print::Ignored
        | Print::SuffixOe
        | Print::SuffixRc
        | Print::SuffixLk
        | Print::SuffixAa => return None,
    })
}

/// Prints an instruction with the operands its row lists.
fn from_table(row: &OpcodeInfo, word: u32, address: Option<u32>) -> String {
    let name = with_suffixes(row, word);
    let takes_operands = row.fields.iter().any(|f| arg_of(f, word).is_some());
    if !takes_operands {
        return bare(&name);
    }
    let skip_optional = row
        .fields
        .iter()
        .all(|f| f.print != Print::Optional || f.get(word) == 0);
    let mut out = padded_name(&name);
    let mut operands = Operands {
        out: &mut out,
        address,
        first: true,
        open_paren: false,
    };
    for field in row.fields {
        if skip_optional && field.print == Print::Optional {
            continue;
        }
        if let Some(arg) = arg_of(field, word) {
            operands.write(arg);
        }
    }
    out
}

/// The condition a BI field and a BO "branch if true" bit stand for.
fn condition(bo: u8, bi: CrBit) -> &'static str {
    const IF_TRUE: [&str; 4] = ["lt", "gt", "eq", "so"];
    const IF_FALSE: [&str; 4] = ["ge", "le", "ne", "ns"];
    let names = if bo & 8 != 0 { IF_TRUE } else { IF_FALSE };
    names[usize::from(bi.0 & 3)]
}

/// The `+` or `-` that a BO field with these low bits asks for, if any.
fn cond_hint(bo: u8) -> &'static str {
    match bo & 3 {
        2 => "-",
        3 => "+",
        _ => "",
    }
}

/// The condition register field operand, which objdump leaves out for `cr0`.
fn cr_operand(bi: CrBit) -> Option<Arg> {
    (bi.0 >> 2 != 0).then_some(Arg::Cr(CrField(bi.0 >> 2)))
}

/// `bc`, with its many simplified mnemonics.
fn conditional_branch(
    bo: u8,
    bi: CrBit,
    bd: i16,
    aa: bool,
    lk: bool,
    address: Option<u32>,
) -> String {
    let target = if aa {
        // Sign extension is the intent: the address prints as 32 bits.
        Arg::Absolute(i32::from(bd) as u32)
    } else {
        Arg::Relative(i32::from(bd))
    };
    let suffix = match (lk, aa) {
        (false, false) => "",
        (true, false) => "l",
        (false, true) => "a",
        (true, true) => "la",
    };
    let hint = if bo & 1 != 0 { "+" } else { "-" };
    match bo {
        0..=3 | 8..=11 => {
            let counter = if bo & 2 != 0 { "bdz" } else { "bdnz" };
            let sense = if bo & 8 != 0 { "t" } else { "f" };
            let name = format!("{counter}{sense}{suffix}");
            line(&name, &[Arg::Bit(bi), target], address)
        }
        4..=7 | 12..=15 => {
            let name = format!("b{}{suffix}{}", condition(bo, bi), cond_hint(bo));
            match cr_operand(bi) {
                Some(cr) => line(&name, &[cr, target], address),
                None => line(&name, &[target], address),
            }
        }
        16..=19 | 24..=27 if bi.0 == 0 => {
            let counter = if bo & 2 != 0 { "bdz" } else { "bdnz" };
            let hint = if bo >= 24 { hint } else { "" };
            line(&format!("{counter}{suffix}{hint}"), &[target], address)
        }
        24..=27 => {
            let name = format!("bc{suffix}{hint}");
            let args = [Arg::Int(i32::from(bo & !1)), Arg::Bit(bi), target];
            line(&name, &args, address)
        }
        _ => {
            let args = [Arg::Int(i32::from(bo)), Arg::Bit(bi), target];
            line(&format!("bc{suffix}"), &args, address)
        }
    }
}

/// `bclr` and `bcctr`, whose simplified mnemonics only differ in a few places.
fn register_branch(is_lr: bool, bo: u8, bi: CrBit, bh: u8, lk: bool) -> String {
    let (generic, reg) = if is_lr {
        ("bclr", "lr")
    } else {
        ("bcctr", "ctr")
    };
    let l = if lk { "l" } else { "" };
    let bo_arg = Arg::Int(i32::from(bo));
    if bh != 0 {
        let args = [bo_arg, Arg::Bit(bi), Arg::Int(i32::from(bh))];
        return line(&format!("{generic}{l}"), &args, None);
    }
    let hint = if bo & 1 != 0 { "+" } else { "-" };
    let generic_hinted = || {
        let args = [Arg::Int(i32::from(bo & !1)), Arg::Bit(bi)];
        line(&format!("{generic}{l}{hint}"), &args, None)
    };
    match bo {
        0 | 2 | 8 | 10 if is_lr => {
            let counter = if bo & 2 != 0 { "bdz" } else { "bdnz" };
            let sense = if bo & 8 != 0 { "t" } else { "f" };
            line(&format!("{counter}{sense}lr{l}"), &[Arg::Bit(bi)], None)
        }
        4 | 6 | 7 | 12 | 14 | 15 => {
            let name = format!("b{}{reg}{l}{}", condition(bo, bi), cond_hint(bo));
            match cr_operand(bi) {
                Some(cr) => line(&name, &[cr], None),
                None => line(&name, &[], None),
            }
        }
        20 if bi.0 == 0 => bare(&format!("b{reg}{l}")),
        16 | 18 | 24..=27 if is_lr && bi.0 == 0 => {
            let counter = if bo & 2 != 0 { "bdz" } else { "bdnz" };
            let hint = if bo >= 24 { hint } else { "" };
            bare(&format!("{counter}lr{l}{hint}"))
        }
        _ => generic_hinted(),
    }
}

/// The condition of a trap, for the values objdump has a name for.
fn trap_condition(to: u8) -> Option<&'static str> {
    Some(match to {
        1 => "lgt",
        2 => "llt",
        4 => "eq",
        5 => "lge",
        6 => "lle",
        8 => "gt",
        12 => "ge",
        16 => "lt",
        20 => "le",
        24 => "ne",
        31 => "u",
        _ => return None,
    })
}

/// A comparison, whose `L` field picks the mnemonic and whose `cr0` target is left out.
fn compare(name: &str, bf: CrField, second: Arg, third: Arg, address: Option<u32>) -> String {
    if bf.0 == 0 {
        line(name, &[second, third], address)
    } else {
        line(name, &[Arg::Cr(bf), second, third], address)
    }
}

/// The mnemonic and printed number of a numbered special purpose register.
fn numbered_spr(spr: u16) -> Option<(&'static str, u16)> {
    spr::NUMBERED
        .iter()
        .find_map(|&(first, count, step, name)| {
            let offset = spr.checked_sub(first)?;
            (offset < count && offset % step == 0).then_some((name, offset / step))
        })
}

/// The name objdump gives a special purpose register in this table.
fn named_spr(table: &'static [(u16, &'static str)], spr: u16) -> Option<&'static str> {
    table
        .iter()
        .find_map(|&(number, name)| (number == spr).then_some(name))
}

/// A dot if the record bit is set.
fn dot(rc: bool) -> &'static str {
    if rc { "." } else { "" }
}

/// Prints an instruction with a simplified mnemonic, if its operands call for one.
fn simplified(insn: &Insn, address: Option<u32>) -> Option<String> {
    use Arg::{Bit, Int, R, R0, Relative, V};
    let int = |value: u8| Int(i32::from(value));
    Some(match *insn {
        Insn::B { li, aa, lk } => {
            let name = match (lk, aa) {
                (false, false) => "b",
                (true, false) => "bl",
                (false, true) => "ba",
                (true, true) => "bla",
            };
            // The cast keeps the bits, as objdump prints the address as 32 bits.
            let target = if aa {
                Arg::Absolute(li as u32)
            } else {
                Relative(li)
            };
            line(name, &[target], address)
        }
        Insn::Bc { bo, bi, bd, aa, lk } => conditional_branch(bo, bi, bd, aa, lk, address),
        Insn::Bclr { bo, bi, bh, lk } => register_branch(true, bo, bi, bh, lk),
        Insn::Bcctr { bo, bi, bh, lk } => register_branch(false, bo, bi, bh, lk),

        Insn::Addi { rt, ra: Gpr(0), si } => line("li", &[R(rt), Int(i32::from(si))], address),
        Insn::Addis { rt, ra: Gpr(0), si } => line("lis", &[R(rt), Int(i32::from(si))], address),
        Insn::Ori {
            ra: Gpr(0),
            rs: Gpr(0),
            ui: 0,
        } => bare("nop"),
        Insn::Xori {
            ra: Gpr(0),
            rs: Gpr(0),
            ui: 0,
        } => bare("xnop"),
        Insn::Or { ra, rs, rb, rc } if rs == rb => match (ra.0, rs.0, rc) {
            (27, 27, false) => bare("yield"),
            (29, 29, false) => bare("mdoio"),
            (30, 30, false) => bare("mdoom"),
            _ => line(&format!("mr{}", dot(rc)), &[R(ra), R(rs)], address),
        },
        Insn::Nor { ra, rs, rb, rc } if rs == rb => {
            line(&format!("not{}", dot(rc)), &[R(ra), R(rs)], address)
        }

        Insn::Cmp { bf, l, ra, rb } => {
            compare(if l { "cmpd" } else { "cmpw" }, bf, R(ra), R(rb), address)
        }
        Insn::Cmpl { bf, l, ra, rb } => {
            compare(if l { "cmpld" } else { "cmplw" }, bf, R(ra), R(rb), address)
        }
        Insn::Cmpi { bf, l, ra, si, .. } => {
            let name = if l { "cmpdi" } else { "cmpwi" };
            compare(name, bf, R(ra), Int(i32::from(si)), address)
        }
        Insn::Cmpli { bf, l, ra, ui, .. } => {
            let name = if l { "cmpldi" } else { "cmplwi" };
            compare(name, bf, R(ra), Int(i32::from(ui)), address)
        }

        Insn::Tw { to, ra, rb } => {
            let condition = trap_condition(to)?;
            line(&format!("tw{condition}"), &[R(ra), R(rb)], address)
        }
        Insn::Td { to, ra, rb } => {
            let condition = trap_condition(to)?;
            line(&format!("td{condition}"), &[R(ra), R(rb)], address)
        }
        Insn::Twi { to, ra, si } => {
            let condition = trap_condition(to)?;
            let args = [R(ra), Int(i32::from(si))];
            line(&format!("tw{condition}i"), &args, address)
        }
        Insn::Tdi { to, ra, si } => {
            let condition = trap_condition(to)?;
            let args = [R(ra), Int(i32::from(si))];
            line(&format!("td{condition}i"), &args, address)
        }

        Insn::Rlwinm {
            ra,
            rs,
            sh,
            mb: 0,
            me: 31,
            rc,
        } => line(
            &format!("rotlwi{}", dot(rc)),
            &[R(ra), R(rs), int(sh)],
            address,
        ),
        Insn::Rlwinm {
            ra,
            rs,
            sh: 0,
            mb,
            me: 31,
            rc,
        } => line(
            &format!("clrlwi{}", dot(rc)),
            &[R(ra), R(rs), int(mb)],
            address,
        ),
        Insn::Rlwnm {
            ra,
            rs,
            rb,
            mb: 0,
            me: 31,
            rc,
        } => line(
            &format!("rotlw{}", dot(rc)),
            &[R(ra), R(rs), R(rb)],
            address,
        ),
        Insn::Rldicl {
            ra,
            rs,
            sh,
            mb: 0,
            rc,
        } => line(
            &format!("rotldi{}", dot(rc)),
            &[R(ra), R(rs), int(sh)],
            address,
        ),
        Insn::Rldicl {
            ra,
            rs,
            sh: 0,
            mb,
            rc,
        } => line(
            &format!("clrldi{}", dot(rc)),
            &[R(ra), R(rs), int(mb)],
            address,
        ),
        Insn::Rldcl {
            ra,
            rs,
            rb,
            mb: 0,
            rc,
        } => line(
            &format!("rotld{}", dot(rc)),
            &[R(ra), R(rs), R(rb)],
            address,
        ),

        Insn::Mfspr { rt, spr } => {
            if let Some((name, number)) = numbered_spr(spr) {
                let args = [R(rt), Int(i32::from(number))];
                line(&format!("mf{name}"), &args, address)
            } else {
                let name = named_spr(spr::MOVE_FROM, spr)?;
                line(&format!("mf{name}"), &[R(rt)], address)
            }
        }
        Insn::Mtspr { spr, rs } => {
            if let Some((name, number)) = numbered_spr(spr) {
                let args = [Int(i32::from(number)), R(rs)];
                line(&format!("mt{name}"), &args, address)
            } else {
                let name = named_spr(spr::MOVE_TO, spr)?;
                line(&format!("mt{name}"), &[R(rs)], address)
            }
        }
        Insn::Mftb { rt, tbr } => line(
            if tbr == 269 { "mftbu" } else { "mftbl" },
            &[R(rt)],
            address,
        ),
        Insn::Mtcrf { fxm: 0xFF, rs } => line("mtcr", &[R(rs)], address),

        Insn::Creqv { bt, ba, bb } if bt == ba && ba == bb => line("crset", &[Bit(bt)], address),
        Insn::Crxor { bt, ba, bb } if bt == ba && ba == bb => line("crclr", &[Bit(bt)], address),
        Insn::Cror { bt, ba, bb } if ba == bb => line("crmove", &[Bit(bt), Bit(ba)], address),
        Insn::Crnor { bt, ba, bb } if ba == bb => line("crnot", &[Bit(bt), Bit(ba)], address),

        Insn::Sync { l: 1 } => bare("lwsync"),
        Insn::Sync { l: 2 } => bare("ptesync"),
        Insn::Dcbf { ra, rb, l } => match l {
            1 => line("dcbfl", &[R0(ra), R(rb)], address),
            3 => line("dcbf", &[R0(ra), R(rb), Int(1)], address),
            _ => line("dcbf", &[R0(ra), R(rb)], address),
        },
        Insn::Dcbt { ra, rb, th: 16 } => line("dcbtt", &[R0(ra), R(rb)], address),
        Insn::Dcbtst { ra, rb, th: 16 } => line("dcbtstt", &[R0(ra), R(rb)], address),
        Insn::Dst {
            t, ra, rb, strm, ..
        } => {
            let args = [R(ra), R(rb), int(strm)];
            line(if t { "dstt" } else { "dst" }, &args, address)
        }
        Insn::Dstst {
            t, ra, rb, strm, ..
        } => {
            let args = [R(ra), R(rb), int(strm)];
            line(if t { "dststt" } else { "dstst" }, &args, address)
        }
        Insn::Dss { all: true, .. } => bare("dssall"),
        Insn::Dss {
            all: false, strm, ..
        } => line("dss", &[int(strm)], address),

        Insn::Vor { vd, va, vb } if va == vb => line("vmr", &[V(vd), V(va)], address),

        // objdump writes the destination again as a fourth operand, since it is also a source.
        Insn::Vmaddfp128 { vd, va, vb } => {
            line("vmaddfp128", &[V(vd), V(va), V(vb), V(vd)], address)
        }
        Insn::Vmaddcfp128 { vd, va, vb } => {
            line("vmaddcfp128", &[V(vd), V(va), V(vd), V(vb)], address)
        }
        Insn::Vnmsubfp128 { vd, va, vb } => {
            line("vnmsubfp128", &[V(vd), V(va), V(vb), V(vd)], address)
        }
        Insn::Vsel128 { vd, va, vb } => line("vsel128", &[V(vd), V(va), V(vb), V(vd)], address),

        // objdump only prints part of these fields. The word keeps all of them, and so does the
        // instruction, but the text has to match.
        Insn::Vperm128 { vd, va, vb, vc } => {
            line("vperm128", &[V(vd), V(va), V(vb), V(Vr(vc.0 & 3))], address)
        }
        Insn::Vrlimi128 { vd, vb, imm, z } => {
            line("vrlimi128", &[V(vd), V(vb), int(imm), int(z & 2)], address)
        }
        Insn::Vpkd3d128 { vd, vb, imm, z } => {
            let args = [V(vd), V(vb), int((imm >> 2) & 3), int(imm & 2), int(z & 2)];
            line("vpkd3d128", &args, address)
        }

        // objdump has no names for these two Xenon instructions.
        Insn::Dcbz128 { ra, rb } => line("dcbzl", &[R0(ra), R(rb)], address),
        Insn::Mtmsree { rs } => line("mtmsrd", &[R(rs), Int(1)], address),

        _ => return None,
    })
}
