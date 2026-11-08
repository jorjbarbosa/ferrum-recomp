// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use ferrum_decoder::{CrBit, Fpr, Gpr, Insn, Vr};

use super::*;

const BASE: u32 = 0x8200_0000;

fn blr() -> Insn {
    Insn::Bclr {
        bo: 20,
        bi: CrBit(0),
        bh: 0,
        lk: false,
    }
}

fn std(rs: u8, ds: i16) -> Insn {
    Insn::Std {
        rs: Gpr(rs),
        ds,
        ra: Gpr(1),
    }
}

fn ld(rt: u8, ds: i16) -> Insn {
    Insn::Ld {
        rt: Gpr(rt),
        ds,
        ra: Gpr(1),
    }
}

/// The GPR chains with the layout of the 64-bit ABI: r14 at -0x98 off r1, LR at -0x8.
fn save_gpr_chain() -> Vec<Insn> {
    let mut insns: Vec<Insn> = (14..32)
        .map(|r| std(r, -0x98 + 8 * (i16::from(r) - 14)))
        .collect();
    insns.push(Insn::Stw {
        rs: Gpr(12),
        d: -8,
        ra: Gpr(1),
    });
    insns.push(blr());
    insns
}

fn restore_gpr_chain() -> Vec<Insn> {
    let mut insns: Vec<Insn> = (14..32)
        .map(|r| ld(r, -0x98 + 8 * (i16::from(r) - 14)))
        .collect();
    insns.push(Insn::Lwz {
        rt: Gpr(12),
        d: -8,
        ra: Gpr(1),
    });
    insns.push(Insn::Mtspr {
        spr: 8,
        rs: Gpr(12),
    });
    insns.push(blr());
    insns
}

fn vmx_chain(first: u8, count: u8, save: bool) -> Vec<Insn> {
    let mut insns = Vec::new();
    for k in 0..count {
        let v = Vr(first + k);
        insns.push(Insn::Addi {
            rt: Gpr(11),
            ra: Gpr(0),
            si: -0x400 + 16 * i16::from(k),
        });
        let (ra, rb) = (Gpr(11), Gpr(12));
        insns.push(match (save, first >= 32) {
            (true, false) => Insn::Stvx { vs: v, ra, rb },
            (true, true) => Insn::Stvx128 { vs: v, ra, rb },
            (false, false) => Insn::Lvx { vd: v, ra, rb },
            (false, true) => Insn::Lvx128 { vd: v, ra, rb },
        });
    }
    insns.push(blr());
    insns
}

fn find(insns: &[Insn]) -> SaveRestore {
    let bytes: Vec<u8> = insns
        .iter()
        .flat_map(|insn| insn.encode().to_be_bytes())
        .collect();
    find_save_restore(&Code::new(BASE, &bytes))
}

/// Address, family, register and end of every entry found.
fn entries(found: &SaveRestore) -> Vec<(u32, Family, u8, u32)> {
    found
        .iter()
        .map(|(&addr, r)| (addr - BASE, r.family, r.register, r.end - BASE))
        .collect()
}

#[test]
fn gpr_chains_give_one_entry_per_register() {
    // Some other code first, so that the chains do not start at the base.
    let mut insns = vec![blr(), blr()];
    insns.extend(save_gpr_chain());
    insns.extend(restore_gpr_chain());
    let found = entries(&find(&insns));
    assert_eq!(found.len(), 36);
    assert_eq!(found[0], (8, Family::SaveGprLr, 14, 8 + 19 * 4));
    assert_eq!(found[17], (8 + 17 * 4, Family::SaveGprLr, 31, 8 + 19 * 4));
    let restore = 8 + 20 * 4;
    assert_eq!(
        found[18],
        (restore, Family::RestoreGprLr, 14, restore + 20 * 4)
    );
    assert_eq!(
        found[35],
        (restore + 17 * 4, Family::RestoreGprLr, 31, restore + 20 * 4)
    );
}

#[test]
fn fpr_chains_end_in_blr() {
    let mut insns: Vec<Insn> = (14..32)
        .map(|f| Insn::Stfd {
            frs: Fpr(f),
            d: -0x90 + 8 * (i16::from(f) - 14),
            ra: Gpr(12),
        })
        .collect();
    insns.push(blr());
    insns.extend((14..32).map(|f| Insn::Lfd {
        frt: Fpr(f),
        d: -0x90 + 8 * (i16::from(f) - 14),
        ra: Gpr(12),
    }));
    insns.push(blr());
    let found = entries(&find(&insns));
    assert_eq!(found.len(), 36);
    assert_eq!(found[0], (0, Family::SaveFpr, 14, 18 * 4));
    assert_eq!(found[18], (19 * 4, Family::RestoreFpr, 14, 37 * 4));
}

#[test]
fn vmx_chains_pair_li_with_the_access() {
    let mut insns = vmx_chain(14, 18, true);
    insns.extend(vmx_chain(64, 64, false));
    let found = entries(&find(&insns));
    assert_eq!(found.len(), 18 + 64);
    assert_eq!(found[0], (0, Family::SaveVmx, 14, 36 * 4));
    assert_eq!(found[1], (8, Family::SaveVmx, 15, 36 * 4));
    let restore = 37 * 4;
    assert_eq!(
        found[18],
        (restore, Family::RestoreVmx, 64, restore + 128 * 4)
    );
    assert_eq!(
        found[81],
        (restore + 63 * 8, Family::RestoreVmx, 127, restore + 128 * 4)
    );
}

#[test]
fn a_chain_that_does_not_line_up_is_not_a_routine() {
    let broken: [fn(&mut Vec<Insn>); 7] = [
        // A prologue with only the first store, as normal code has.
        |insns| insns.truncate(1),
        // No blr at the end.
        |insns| {
            *insns.last_mut().unwrap() = Insn::Ori {
                ra: Gpr(0),
                rs: Gpr(0),
                ui: 0,
            }
        },
        // Registers out of order.
        |insns| insns.swap(3, 4),
        // One slot off.
        |insns| insns[5] = std(19, 0),
        // Another base register.
        |insns| {
            insns[6] = Insn::Std {
                rs: Gpr(20),
                ds: -0x98 + 48,
                ra: Gpr(12),
            }
        },
        // The link register to the wrong slot.
        |insns| {
            insns[18] = Insn::Stw {
                rs: Gpr(12),
                d: -4,
                ra: Gpr(1),
            }
        },
        // A conditional return instead of blr.
        |insns| {
            *insns.last_mut().unwrap() = Insn::Bclr {
                bo: 12,
                bi: CrBit(2),
                bh: 0,
                lk: false,
            }
        },
    ];
    for (index, breakage) in broken.iter().enumerate() {
        let mut insns = save_gpr_chain();
        breakage(&mut insns);
        assert!(find(&insns).is_empty(), "breakage {index}");
    }
    let mut vmx = vmx_chain(14, 18, true);
    vmx[2] = Insn::Addi {
        rt: Gpr(11),
        ra: Gpr(0),
        si: 0,
    };
    assert!(find(&vmx).is_empty(), "an offset that does not step by 16");
    let mut restore = restore_gpr_chain();
    restore[19] = Insn::Mtspr {
        spr: 9,
        rs: Gpr(12),
    };
    assert!(find(&restore).is_empty(), "mtctr instead of mtlr");
}
