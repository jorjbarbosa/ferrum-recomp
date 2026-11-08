// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Which general-purpose registers an instruction writes.
//!
//! Jump table detection evaluates a few instructions symbolically and has to forget what it knows
//! about every register that anything else writes. The rows of the opcode table do not say which
//! operand is a destination, so this module lists every instruction that names a GPR, by the role
//! of its fields in the PowerPC ISA 2.02 books: `rt` is written by arithmetic, loads and moves
//! from special registers, `ra` by logical, rotate and shift instructions, and the base register
//! by the update forms of loads and stores. An instruction that names no GPR writes none.

use ferrum_decoder::Insn;

/// The GPRs an instruction writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Writes {
    /// The registers whose bits are set, register N at bit N.
    Some(u32),
    /// Possibly any register: `lswi` and `lswx` write a run whose length comes from an operand or
    /// from XER.
    All,
}

impl Writes {
    /// Returns whether register `reg` may be written.
    pub(crate) fn contains(self, reg: u8) -> bool {
        match self {
            Writes::Some(mask) => mask & (1 << reg) != 0,
            Writes::All => true,
        }
    }
}

/// Returns the GPRs `insn` writes.
pub(crate) fn gpr_writes(insn: &Insn) -> Writes {
    gpr_effect(insn).unwrap_or(Writes::Some(0))
}

fn one(reg: u8) -> Writes {
    Writes::Some(1 << reg)
}

/// The GPRs `insn` writes, or `None` if its row names no GPR, so that a test can check that every
/// row naming one is listed here.
fn gpr_effect(insn: &Insn) -> Option<Writes> {
    use Insn::*;
    Some(match *insn {
        // rt: arithmetic, loads and moves from special registers.
        Mulli { rt, .. }
        | Subfic { rt, .. }
        | Addic { rt, .. }
        | AddicDot { rt, .. }
        | Addi { rt, .. }
        | Addis { rt, .. }
        | Lwz { rt, .. }
        | Lbz { rt, .. }
        | Lhz { rt, .. }
        | Lha { rt, .. }
        | Ld { rt, .. }
        | Lwa { rt, .. }
        | Neg { rt, .. }
        | Subfze { rt, .. }
        | Addze { rt, .. }
        | Subfme { rt, .. }
        | Addme { rt, .. }
        | Mulhdu { rt, .. }
        | Mulhwu { rt, .. }
        | Mulhd { rt, .. }
        | Mulhw { rt, .. }
        | Subfc { rt, .. }
        | Addc { rt, .. }
        | Subf { rt, .. }
        | Subfe { rt, .. }
        | Adde { rt, .. }
        | Mulld { rt, .. }
        | Mullw { rt, .. }
        | Add { rt, .. }
        | Divdu { rt, .. }
        | Divwu { rt, .. }
        | Divd { rt, .. }
        | Divw { rt, .. }
        | Lwarx { rt, .. }
        | Ldx { rt, .. }
        | Lwzx { rt, .. }
        | Ldarx { rt, .. }
        | Lbzx { rt, .. }
        | Lhzx { rt, .. }
        | Lwax { rt, .. }
        | Lhax { rt, .. }
        | Ldbrx { rt, .. }
        | Lwbrx { rt, .. }
        | Lhbrx { rt, .. }
        | Mfcr { rt, .. }
        | Mfmsr { rt, .. }
        | Slbmfev { rt, .. }
        | Slbmfee { rt, .. }
        | Eciwx { rt, .. }
        | Mfocrf { rt, .. }
        | Mfspr { rt, .. }
        | Mftb { rt, .. } => one(rt.0),
        // rt and the base register: loads with update.
        Lwzu { rt, ra, .. }
        | Lbzu { rt, ra, .. }
        | Lhzu { rt, ra, .. }
        | Lhau { rt, ra, .. }
        | Ldu { rt, ra, .. }
        | Ldux { rt, ra, .. }
        | Lwzux { rt, ra, .. }
        | Lbzux { rt, ra, .. }
        | Lhzux { rt, ra, .. }
        | Lwaux { rt, ra, .. }
        | Lhaux { rt, ra, .. } => Writes::Some(1 << rt.0 | 1 << ra.0),
        // ra: logical, rotate and shift instructions, and the base register of the other update
        // forms.
        Ori { ra, .. }
        | Oris { ra, .. }
        | Xori { ra, .. }
        | Xoris { ra, .. }
        | AndiDot { ra, .. }
        | AndisDot { ra, .. }
        | Slw { ra, .. }
        | Cntlzw { ra, .. }
        | Sld { ra, .. }
        | And { ra, .. }
        | Cntlzd { ra, .. }
        | Andc { ra, .. }
        | Popcntb { ra, .. }
        | Nor { ra, .. }
        | Eqv { ra, .. }
        | Xor { ra, .. }
        | Orc { ra, .. }
        | Or { ra, .. }
        | Nand { ra, .. }
        | Srw { ra, .. }
        | Srd { ra, .. }
        | Sraw { ra, .. }
        | Srad { ra, .. }
        | Srawi { ra, .. }
        | Extsh { ra, .. }
        | Extsb { ra, .. }
        | Extsw { ra, .. }
        | Sradi { ra, .. }
        | Rlwimi { ra, .. }
        | Rlwinm { ra, .. }
        | Rlwnm { ra, .. }
        | Rldicl { ra, .. }
        | Rldicr { ra, .. }
        | Rldic { ra, .. }
        | Rldimi { ra, .. }
        | Rldcl { ra, .. }
        | Rldcr { ra, .. }
        | Stwu { ra, .. }
        | Stbu { ra, .. }
        | Sthu { ra, .. }
        | Stdu { ra, .. }
        | Stdux { ra, .. }
        | Stwux { ra, .. }
        | Stbux { ra, .. }
        | Sthux { ra, .. }
        | Lfsu { ra, .. }
        | Lfdu { ra, .. }
        | Stfsu { ra, .. }
        | Stfdu { ra, .. }
        | Lfsux { ra, .. }
        | Lfdux { ra, .. }
        | Stfsux { ra, .. }
        | Stfdux { ra, .. } => one(ra.0),
        // `lmw` loads rt to r31.
        Lmw { rt, .. } => Writes::Some(u32::MAX << rt.0),
        Lswi { .. } | Lswx { .. } => Writes::All,
        // Instructions that only read the GPRs they name.
        Tdi { .. }
        | Twi { .. }
        | Cmpli { .. }
        | Cmpi { .. }
        | Stw { .. }
        | Stb { .. }
        | Sth { .. }
        | Stmw { .. }
        | Lfs { .. }
        | Lfd { .. }
        | Stfs { .. }
        | Stfd { .. }
        | Std { .. }
        | Cmp { .. }
        | Cmpl { .. }
        | Tw { .. }
        | Td { .. }
        | Stdx { .. }
        | StwcxDot { .. }
        | Stwx { .. }
        | StdcxDot { .. }
        | Stbx { .. }
        | Sthx { .. }
        | Stdbrx { .. }
        | Stswx { .. }
        | Stwbrx { .. }
        | Stswi { .. }
        | Sthbrx { .. }
        | Lfsx { .. }
        | Lfdx { .. }
        | Stfsx { .. }
        | Stfdx { .. }
        | Stfiwx { .. }
        | Mtmsr { .. }
        | Mtmsrd { .. }
        | Mtmsree { .. }
        | Tlbiel { .. }
        | Tlbie { .. }
        | Slbmte { .. }
        | Slbie { .. }
        | Dcbst { .. }
        | Dcbf { .. }
        | Dcbtst { .. }
        | Dcbt { .. }
        | Ecowx { .. }
        | Dcbi { .. }
        | Dcba { .. }
        | Icbi { .. }
        | Dcbz { .. }
        | Dcbz128 { .. }
        | Mtcrf { .. }
        | Mtocrf { .. }
        | Mtspr { .. }
        | Dst { .. }
        | Dstst { .. }
        | Lvsl { .. }
        | Lvsr { .. }
        | Lvebx { .. }
        | Lvehx { .. }
        | Lvewx { .. }
        | Lvx { .. }
        | Lvxl { .. }
        | Stvebx { .. }
        | Stvehx { .. }
        | Stvewx { .. }
        | Stvx { .. }
        | Stvxl { .. }
        | Lvlx { .. }
        | Lvrx { .. }
        | Lvlxl { .. }
        | Lvrxl { .. }
        | Stvlx { .. }
        | Stvrx { .. }
        | Stvlxl { .. }
        | Stvrxl { .. }
        | Lvsl128 { .. }
        | Lvsr128 { .. }
        | Lvewx128 { .. }
        | Lvx128 { .. }
        | Lvxl128 { .. }
        | Stvewx128 { .. }
        | Stvx128 { .. }
        | Stvxl128 { .. }
        | Lvlx128 { .. }
        | Lvrx128 { .. }
        | Lvlxl128 { .. }
        | Lvrxl128 { .. }
        | Stvlx128 { .. }
        | Stvrx128 { .. }
        | Stvlxl128 { .. }
        | Stvrxl128 { .. } => Writes::Some(0),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use ferrum_decoder::{Gpr, OPCODES, decode, format};

    use super::*;

    /// Spreads the low bits of `value` over the set bits of `mask`, lowest first.
    fn deposit(mut value: u32, mask: u32) -> u32 {
        let mut out = 0;
        for bit in (0..32).filter(|bit| mask & (1 << bit) != 0) {
            out |= (value & 1) << bit;
            value >>= 1;
        }
        out
    }

    /// Every row that names a GPR is listed, and no other: with every field bit set, a GPR field
    /// is r31, and only GPR operands print as `r31`.
    #[test]
    fn every_row_that_names_a_gpr_is_listed() {
        let mut checked = 0;
        for info in OPCODES {
            // Some fields reserve values (BO of a branch, the SPR of mftb), so fewer bits are
            // tried until a word decodes, keeping the register fields at 31.
            let variable = !info.mask;
            let insn = [0xFFFF_FFFF, 0x03FF_F800, 0x001F_F800]
                .into_iter()
                .find_map(|bits| decode(info.value | (variable & bits)))
                .or_else(|| {
                    // One register field at 31, the other bits counted up.
                    [0x03E0_0000, 0x001F_0000, 0x0000_F800]
                        .into_iter()
                        .find_map(|field| {
                            let field = variable & field;
                            (0..=0xFFFF).find_map(|k| {
                                decode(info.value | field | deposit(k, variable & !field))
                            })
                        })
                })
                .unwrap_or_else(|| panic!("no word of {} decodes", info.mnemonic));
            assert_eq!(insn.opcode(), info.opcode);
            let names_gpr = format(&insn).contains("r31");
            assert_eq!(
                gpr_effect(&insn).is_some(),
                names_gpr,
                "{}: {}",
                info.mnemonic,
                format(&insn)
            );
            checked += usize::from(names_gpr);
        }
        assert_eq!(checked, 210, "rows that name a GPR");
    }

    #[test]
    fn destinations_follow_the_role_of_the_field() {
        let rt = |insn: Insn| gpr_writes(&insn);
        // addi r3,r4,1 writes r3; ori r5,r6,0 writes r5; lwzu r7,8(r1) writes r7 and r1.
        assert_eq!(
            rt(Insn::Addi {
                rt: Gpr(3),
                ra: Gpr(4),
                si: 1
            }),
            Writes::Some(1 << 3)
        );
        assert_eq!(
            rt(Insn::Ori {
                ra: Gpr(5),
                rs: Gpr(6),
                ui: 0
            }),
            Writes::Some(1 << 5)
        );
        assert_eq!(
            rt(Insn::Lwzu {
                rt: Gpr(7),
                d: 8,
                ra: Gpr(1)
            }),
            Writes::Some(1 << 7 | 1 << 1)
        );
        // stw writes nothing; lmw r29 writes r29 to r31; lswi may write anything.
        assert_eq!(
            rt(Insn::Stw {
                rs: Gpr(3),
                d: 0,
                ra: Gpr(1)
            }),
            Writes::Some(0)
        );
        let lmw = rt(Insn::Lmw {
            rt: Gpr(29),
            d: 0,
            ra: Gpr(1),
        });
        assert!(lmw.contains(29) && lmw.contains(31) && !lmw.contains(28));
        assert!(
            rt(Insn::Lswi {
                rt: Gpr(3),
                ra: Gpr(4),
                nb: 8
            })
            .contains(0)
        );
    }
}
