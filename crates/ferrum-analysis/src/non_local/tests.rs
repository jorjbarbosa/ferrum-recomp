// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use ferrum_decoder::{CrBit, Gpr, Insn};

use super::*;
use crate::asm::{assemble, b, blr, cmpwi, li, lis, lwz, mtctr};

const BASE: u32 = 0x8200_0000;
/// Offsets in the test image.
const SETJMP: u32 = 0x100;
const LONGJMP: u32 = 0x300;
const HELPER: u32 = 0x500;
const SIZE: usize = 0x800;

/// The buffer of these tests, which is not the C runtime's: r1 at 0x10, r14 to r31 from 0x20,
/// the link register after them.
const R1_SLOT: i16 = 0x10;
const LR_SLOT: i16 = 0xB0;

fn gpr_slot(reg: u8) -> i16 {
    0x20 + 8 * (i16::from(reg) - 14)
}

fn std(rs: u8, ds: i16, ra: u8) -> Insn {
    Insn::Std {
        rs: Gpr(rs),
        ds,
        ra: Gpr(ra),
    }
}

fn stw(rs: u8, d: i16, ra: u8) -> Insn {
    Insn::Stw {
        rs: Gpr(rs),
        d,
        ra: Gpr(ra),
    }
}

fn ld(rt: u8, ds: i16, ra: u8) -> Insn {
    Insn::Ld {
        rt: Gpr(rt),
        ds,
        ra: Gpr(ra),
    }
}

fn mflr(rt: u8) -> Insn {
    Insn::Mfspr {
        rt: Gpr(rt),
        spr: 8,
    }
}

fn mtlr(rs: u8) -> Insn {
    Insn::Mtspr {
        spr: 8,
        rs: Gpr(rs),
    }
}

fn mr(ra: u8, rs: u8) -> Insn {
    Insn::Or {
        ra: Gpr(ra),
        rs: Gpr(rs),
        rb: Gpr(rs),
        rc: false,
    }
}

fn stwu(rs: u8, d: i16, ra: u8) -> Insn {
    Insn::Stwu {
        rs: Gpr(rs),
        d,
        ra: Gpr(ra),
    }
}

/// `bl` from the offset `from` to the offset `to`.
fn call(from: u32, to: u32) -> Insn {
    b(to as i32 - from as i32, true)
}

/// A `setjmp`, with the C runtime's opening branch through CTR when `hook`.
fn setjmp(hook: bool) -> Vec<Insn> {
    let mut insns = Vec::new();
    if hook {
        insns.extend([
            lis(4, -0x7D38),
            lwz(0, 0x5080, 4),
            cmpwi(0, 0, 0),
            mtctr(0),
            // bnectr
            Insn::Bcctr {
                bo: 4,
                bi: CrBit(2),
                bh: 0,
                lk: false,
            },
        ]);
    }
    insns.push(mflr(0));
    insns.extend((14..32).map(|reg| std(reg, gpr_slot(reg), 3)));
    insns.extend([
        stw(0, LR_SLOT, 3),
        std(1, R1_SLOT, 3),
        // r0 holds 0 from here on: the store after it is no copy of the link register.
        li(0, 0),
        stw(0, 0xB8, 3),
        li(3, 0),
        blr(),
    ]);
    insns
}

/// A `longjmp` that copies the buffer from `buffer` into r7, makes a call, and loads from the
/// slots of [`setjmp`] moved by `shift`, then runs `tail` before its `blr`.
fn longjmp(buffer: u8, shift: i16, tail: &[Insn]) -> Vec<Insn> {
    let mut insns = vec![
        mflr(0),
        stwu(1, -80, 1),
        stw(0, 8, 1),
        mr(6, 4),
        mr(7, buffer),
        call(LONGJMP + 20, HELPER),
    ];
    insns.extend((14..32).map(|reg| ld(reg, gpr_slot(reg) + shift, 7)));
    insns.extend([
        lwz(5, LR_SLOT + shift, 7),
        mtlr(5),
        ld(1, R1_SLOT + shift, 7),
        mr(3, 6),
    ]);
    insns.extend_from_slice(tail);
    insns.push(blr());
    insns
}

/// An image with a caller of both routines at its start, the two routines, and the helper that
/// `longjmp` calls.
fn image(setjmp: &[Insn], longjmp: &[Insn]) -> Vec<u8> {
    let mut bytes = vec![0; SIZE];
    let mut place = |offset: u32, insns: &[Insn]| {
        let code = assemble(insns);
        bytes[offset as usize..offset as usize + code.len()].copy_from_slice(&code);
    };
    place(0, &[call(0, SETJMP), call(4, LONGJMP), blr()]);
    place(SETJMP, setjmp);
    place(LONGJMP, longjmp);
    place(HELPER, &[blr()]);
    bytes
}

fn find(bytes: &[u8]) -> NonLocalRoutines {
    let range = BASE..BASE + bytes.len() as u32;
    find_non_local(&Code::new(BASE, bytes), std::slice::from_ref(&range))
}

/// A change to the code of a routine.
type Change = fn(&mut Vec<Insn>);

fn both() -> NonLocalRoutines {
    NonLocalRoutines {
        setjmp: vec![BASE + SETJMP],
        longjmp: vec![BASE + LONGJMP],
    }
}

#[test]
fn setjmp_and_longjmp_are_found_by_what_they_do() {
    for hook in [false, true] {
        let found = find(&image(&setjmp(hook), &longjmp(3, 0, &[])));
        assert_eq!(found, both(), "hook: {hook}");
    }
}

#[test]
fn setjmp_saves_every_register_without_a_frame_and_returns_zero() {
    let cases: [(&str, Change); 6] = [
        ("r31 not stored", |insns| {
            insns.retain(|insn| *insn != std(31, gpr_slot(31), 3));
        }),
        ("r1 not stored", |insns| {
            insns.retain(|insn| *insn != std(1, R1_SLOT, 3));
        }),
        ("returns 1", |insns| {
            let at = insns.len() - 2;
            insns[at] = li(3, 1);
        }),
        ("builds a frame", |insns| insns.insert(0, stwu(1, -80, 1))),
        ("makes a call", |insns| insns.insert(1, b(0x400, true))),
        // The copy of the link register is gone by the time it is stored.
        ("stores LR after losing it", |insns| {
            let at = insns
                .iter()
                .position(|insn| *insn == stw(0, LR_SLOT, 3))
                .unwrap();
            insns.insert(at, li(0, 0));
        }),
    ];
    for (name, change) in cases {
        let mut insns = setjmp(false);
        change(&mut insns);
        let found = find(&image(&insns, &longjmp(3, 0, &[])));
        assert_eq!(found, NonLocalRoutines::default(), "{name}");
    }
}

#[test]
fn longjmp_loads_from_the_slots_of_setjmp_through_its_first_argument() {
    let mut r20_elsewhere = longjmp(3, 0, &[]);
    for insn in &mut r20_elsewhere {
        if *insn == ld(20, gpr_slot(20), 7) {
            *insn = ld(20, gpr_slot(20) + 0x100, 7);
        }
    }
    let cases: [(&str, Vec<Insn>); 5] = [
        ("other slots", longjmp(3, 8, &[])),
        // The link register comes from its slot, but one GPR does not.
        ("r20 from another slot", r20_elsewhere),
        // A whole context loaded from the structure the second argument points to.
        ("through r4", longjmp(4, 0, &[])),
        // A call after the mtlr changes the link register again.
        ("call after mtlr", longjmp(3, 0, &[b(0x100, true)])),
        ("r14 overwritten", longjmp(3, 0, &[li(14, 0)])),
    ];
    for (name, insns) in cases {
        let found = find(&image(&setjmp(false), &insns));
        assert_eq!(found.setjmp, vec![BASE + SETJMP], "{name}");
        assert_eq!(found.longjmp, Vec::<u32>::new(), "{name}");
    }
}

#[test]
fn only_the_targets_of_calls_are_candidates() {
    let mut bytes = image(&setjmp(false), &longjmp(3, 0, &[]));
    // The caller's two calls become nops.
    let nop = assemble(&[Insn::Ori {
        ra: Gpr(0),
        rs: Gpr(0),
        ui: 0,
    }]);
    bytes[0..4].copy_from_slice(&nop);
    bytes[4..8].copy_from_slice(&nop);
    assert_eq!(find(&bytes), NonLocalRoutines::default());
}

#[test]
fn every_routine_of_the_shape_is_a_candidate() {
    let mut bytes = image(&setjmp(false), &longjmp(3, 0, &[]));
    // A second setjmp at 0x600, called from the helper's place, which now calls it and returns.
    let second = assemble(&setjmp(true));
    bytes[0x600..0x600 + second.len()].copy_from_slice(&second);
    let caller = assemble(&[call(HELPER, 0x600), blr()]);
    let at = HELPER as usize;
    bytes[at..at + caller.len()].copy_from_slice(&caller);
    let found = find(&bytes);
    assert_eq!(found.setjmp, vec![BASE + SETJMP, BASE + 0x600]);
    assert_eq!(found.longjmp, vec![BASE + LONGJMP]);
}
