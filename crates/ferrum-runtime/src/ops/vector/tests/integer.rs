// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::{splat, v, vscr};
use crate::V128;
use crate::ops::*;

#[test]
fn modulo_arithmetic_wraps_per_element() {
    let a = v(0xFF01_7FFF, 0x8000_0001, 0xFFFF_FFFF, 0);
    let b = v(0x0102_0001, 0x8000_FFFF, 0x0000_0001, 1);
    assert_eq!(vaddubm(a, b), v(0x0003_7F00, 0x0000_FF00, 0xFFFF_FF00, 1));
    assert_eq!(vadduhm(a, b), v(0x0003_8000, 0x0000_0000, 0xFFFF_0000, 1));
    assert_eq!(vadduwm(a, b), v(0x0003_8000, 0x0001_0000, 0, 1));
    assert_eq!(vsububm(b, a), v(0x0201_8102, 0x0000_FFFE, 0x0101_0102, 1));
    assert_eq!(vsubuhm(b, a), v(0x0201_8002, 0x0000_FFFE, 0x0001_0002, 1));
    assert_eq!(vsubuwm(b, a), v(0x0200_8002, 0x0000_FFFE, 2, 1));
}

#[test]
fn saturating_arithmetic_clamps_and_sets_sat() {
    // The suite's vaddshs case: 0x7FFF + 1 and 0x8001 + 0x8001 saturate.
    let mut s = vscr(true);
    let a = v(0x7FFF_8001, 0x7FFF_8003, 0x7FFF_8005, 0x8006_8007);
    let b = v(0x0001_8001, 0x1000_0000, 0x4256_8124, 0);
    assert_eq!(
        vaddshs(&mut s, a, b),
        v(0x7FFF_8000, 0x7FFF_8003, 0x7FFF_8000, 0x8006_8007)
    );
    assert!(s.sat());
    // The same values without saturation leave SAT clear.
    let mut s = vscr(true);
    assert_eq!(
        vaddshs(&mut s, splat(0x0001_FFFF), splat(0x0001_0001)),
        splat(0x0002_0000)
    );
    assert!(!s.sat());
    let check = |op: fn(&mut crate::Vscr, V128, V128) -> V128, a: u32, b: u32, r: u32| {
        let mut s = vscr(true);
        assert_eq!(op(&mut s, splat(a), splat(b)), splat(r), "{a:#x}, {b:#x}");
        assert!(s.sat(), "{a:#x}, {b:#x} saturates");
    };
    check(vaddubs, 0xFF00_0000, 0x0100_0000, 0xFF00_0000);
    check(vaddsbs, 0x7F80_0000, 0x01FF_0000, 0x7F80_0000);
    check(vadduhs, 0xFFFF_0000, 0x0001_0000, 0xFFFF_0000);
    check(vadduws, u32::MAX, 1, u32::MAX);
    check(vaddsws, 0x7FFF_FFFF, 1, 0x7FFF_FFFF);
    check(vaddsws, 0x8000_0000, u32::MAX, 0x8000_0000);
    check(vsububs, 0x0000_0000, 0x0100_0000, 0);
    check(vsubsbs, 0x8000_0000, 0x0100_0000, 0x8000_0000);
    check(vsubuhs, 0x0000_0005, 0x0001_0005, 0);
    check(vsubshs, 0x7FFF_0000, 0xFFFF_0000, 0x7FFF_0000);
    check(vsubuws, 0, 1, 0);
    check(vsubsws, 0x8000_0000, 1, 0x8000_0000);
}

#[test]
fn carries_are_one_or_zero() {
    let a = v(u32::MAX, 1, 0, 5);
    let b = v(1, 1, 1, 5);
    assert_eq!(vaddcuw(a, b), v(1, 0, 0, 0));
    // No borrow is a carry of 1: 1 - 1 and 5 - 5 carry, 0 - 1 borrows.
    assert_eq!(vsubcuw(a, b), v(1, 1, 0, 1));
}

#[test]
fn averages_round_up_in_a_wider_type() {
    // Signed bytes: (-128 + -128 + 1) >> 1 = -128, (127 + 127 + 1) >> 1 = 127, (-1 + 0 + 1) >> 1
    // = 0, (-2 + 1 + 1) >> 1 = 0.
    let a = v(0x807F_FFFE, 0, 0, 0);
    let b = v(0x807F_0001, 0, 0, 0);
    assert_eq!(vavgsb(a, b), v(0x807F_0000, 0, 0, 0));
    assert_eq!(vavgub(a, b), v(0x807F_8080, 0, 0, 0));
    // The suite's vavguh case, and its commented-out vavgsh one.
    let a = v(0x0000_0001, 0x0002_0003, 0x0004_0005, 0x0006_0007);
    let b = v(0x0008_0009, 0x000A_000B, 0x000C_000D, 0x000E_000F);
    let r = v(0x0004_0005, 0x0006_0007, 0x0008_0009, 0x000A_000B);
    assert_eq!(vavguh(a, b), r);
    assert_eq!(vavgsh(a, b), r);
    assert_eq!(
        vavgsh(splat(0x8000_FFFF), splat(0x8000_0000)),
        splat(0x8000_0000)
    );
    assert_eq!(vavguw(splat(u32::MAX), splat(u32::MAX)), splat(u32::MAX));
    assert_eq!(vavgsw(splat(u32::MAX), splat(0)), splat(0));
    assert_eq!(
        vavgsw(splat(0x8000_0000), splat(0x8000_0000)),
        splat(0x8000_0000)
    );
}

#[test]
fn extremes_compare_signed_or_unsigned() {
    let a = v(0x80FF_8000, 0x7FFF_FFFF, 0, 0);
    let b = v(0x0101_0001, 0x8000_0000, 0, 0);
    assert_eq!(vmaxub(a, b), v(0x80FF_8001, 0x80FF_FFFF, 0, 0));
    assert_eq!(vmaxsb(a, b), v(0x0101_0001, 0x7F00_0000, 0, 0));
    assert_eq!(vminuh(a, b), v(0x0101_0001, 0x7FFF_0000, 0, 0));
    assert_eq!(vminsh(a, b), v(0x80FF_8000, 0x8000_FFFF, 0, 0));
    assert_eq!(vmaxsw(a, b), v(0x0101_0001, 0x7FFF_FFFF, 0, 0));
    assert_eq!(vminuw(a, b), v(0x0101_0001, 0x7FFF_FFFF, 0, 0));
    assert_eq!(vmaxuw(a, b), v(0x80FF_8000, 0x8000_0000, 0, 0));
    assert_eq!(vminsw(a, b), v(0x80FF_8000, 0x8000_0000, 0, 0));
    assert_eq!(vmaxuh(a, b), v(0x80FF_8000, 0x8000_FFFF, 0, 0));
    assert_eq!(vmaxsh(a, b), v(0x0101_0001, 0x7FFF_0000, 0, 0));
    assert_eq!(vminub(a, b), v(0x0101_0000, 0x7F00_0000, 0, 0));
    assert_eq!(vminsb(a, b), v(0x80FF_8000, 0x80FF_FFFF, 0, 0));
}

#[test]
fn logic_is_bitwise() {
    let a = v(0xFFFF_0101, 0x7070_FFFF, 0x7FFF_FFFF, 0);
    let b = v(0x8008_1010, 0x808F_0020, 0x7FFF_FFF0, 0x8FFF_FFFF);
    assert_eq!(vand(a, b), v(0x8008_0000, 0x0000_0020, 0x7FFF_FFF0, 0));
    assert_eq!(vandc(a, b), v(0x7FF7_0101, 0x7070_FFDF, 0x0000_000F, 0));
    assert_eq!(
        vor(a, b),
        v(0xFFFF_1111, 0xF0FF_FFFF, 0x7FFF_FFFF, 0x8FFF_FFFF)
    );
    assert_eq!(
        vxor(a, b),
        v(0x7FF7_1111, 0xF0FF_FFDF, 0x0000_000F, 0x8FFF_FFFF)
    );
    assert_eq!(
        vnor(a, b),
        v(0x0000_EEEE, 0x0F00_0000, 0x8000_0000, 0x7000_0000)
    );
}

#[test]
fn shifts_and_rotates_take_the_count_modulo_the_element_size() {
    let ones = splat(u32::MAX);
    // Counts 0, 1, 31 and 33 (which is 1).
    let counts = v(0, 1, 31, 33);
    assert_eq!(
        vslw(ones, counts),
        v(u32::MAX, 0xFFFF_FFFE, 0x8000_0000, 0xFFFF_FFFE)
    );
    assert_eq!(vsrw(ones, counts), v(u32::MAX, 0x7FFF_FFFF, 1, 0x7FFF_FFFF));
    let top = splat(0x8000_0001);
    assert_eq!(
        vsraw(top, counts),
        v(0x8000_0001, 0xC000_0000, u32::MAX, 0xC000_0000)
    );
    assert_eq!(vrlw(top, counts), v(0x8000_0001, 3, 0xC000_0000, 3));
    // Halfwords: counts 0, 17 (1), 15, 16 (0).
    let counts = v(0x0000_0011, 0x000F_0010, 0, 0);
    let x = v(0x8001_8001, 0x8001_8001, 0, 0);
    assert_eq!(vslh(x, counts), v(0x8001_0002, 0x8000_8001, 0, 0));
    assert_eq!(vsrh(x, counts), v(0x8001_4000, 0x0001_8001, 0, 0));
    assert_eq!(vsrah(x, counts), v(0x8001_C000, 0xFFFF_8001, 0, 0));
    assert_eq!(vrlh(x, counts), v(0x8001_0003, 0xC000_8001, 0, 0));
    // Bytes: counts 0, 9 (1), 7, 8 (0).
    let counts = v(0x0009_0708, 0, 0, 0);
    let x = v(0x8181_8181, 0, 0, 0);
    assert_eq!(vslb(x, counts), v(0x8102_8081, 0, 0, 0));
    assert_eq!(vsrb(x, counts), v(0x8140_0181, 0, 0, 0));
    assert_eq!(vsrab(x, counts), v(0x81C0_FF81, 0, 0, 0));
    assert_eq!(vrlb(x, counts), v(0x8103_C081, 0, 0, 0));
}

#[test]
fn even_and_odd_multiplies_widen() {
    // Bytes 0xFF, 0x02, 0x80, 0x03 and 0x02, 0xFF, 0x80, 0x03 in word 0.
    let a = v(0xFF02_8003, 0, 0, 0);
    let b = v(0x02FF_8003, 0, 0, 0);
    // Even bytes 0 and 2: 0xFF × 0x02 and 0x80 × 0x80; odd bytes 1 and 3: 0x02 × 0xFF, 3 × 3.
    assert_eq!(vmuleub(a, b), v(0x01FE_4000, 0, 0, 0));
    assert_eq!(vmulesb(a, b), v(0xFFFE_4000, 0, 0, 0));
    assert_eq!(vmuloub(a, b), v(0x01FE_0009, 0, 0, 0));
    assert_eq!(vmulosb(a, b), v(0xFFFE_0009, 0, 0, 0));
    // Halfwords 0xFFFF and 0x0002 against 0x0002 and 0x8000.
    let a = v(0xFFFF_0002, 0, 0, 0);
    let b = v(0x0002_8000, 0, 0, 0);
    assert_eq!(vmuleuh(a, b), v(0x0001_FFFE, 0, 0, 0));
    assert_eq!(vmulesh(a, b), v(0xFFFF_FFFE, 0, 0, 0));
    assert_eq!(vmulouh(a, b), v(0x0001_0000, 0, 0, 0));
    assert_eq!(vmulosh(a, b), v(0xFFFF_0000, 0, 0, 0));
}

#[test]
fn multiply_high_adds_shift_by_15_and_saturate() {
    let mut s = vscr(true);
    // 0.5 × 0.5 in Q15 is 0x2000, plus 0x1000; -1 × -1 is 1, which saturates to 0x7FFF.
    let r = vmhaddshs(
        &mut s,
        v(0x4000_8000, 0x0001_0000, 0, 0),
        v(0x4000_8000, 0x4000_0000, 0, 0),
        v(0x1000_0000, 0, 0, 0),
    );
    assert_eq!(r, v(0x3000_7FFF, 0, 0, 0));
    assert!(s.sat());
    // Rounding adds 0x4000 first: 1 × 0x4000 gives 0 without it and 1 with it.
    let mut s = vscr(true);
    let r = vmhraddshs(&mut s, splat(0x0001_0001), splat(0x4000_3FFF), splat(0));
    assert_eq!(r, splat(0x0001_0000));
    assert!(!s.sat());
    assert_eq!(
        vmladduhm(splat(0xFFFF_0003), splat(0x0002_0004), splat(0x0003_FFFF)),
        splat(0x0001_000B)
    );
}

#[test]
fn multiply_sums_wrap_or_saturate() {
    // 1×5 + 2×6 + 3×7 + 4×8 + 1 = 71.
    let a = v(0x0102_0304, 0, 0, 0);
    let b = v(0x0506_0708, 0, 0, 0);
    let c = v(1, 2, 3, 4);
    assert_eq!(vmsumubm(a, b, c), v(71, 2, 3, 4));
    // Signed -1 × unsigned 255 = -255.
    assert_eq!(
        vmsummbm(v(0xFF00_0000, 0, 0, 0), v(0xFF00_0000, 0, 0, 0), V128::ZERO).0[0],
        (-255i32) as u32
    );
    assert_eq!(
        vmsumuhm(splat(0xFFFF_FFFF), splat(0xFFFF_FFFF), splat(2)),
        splat(0xFFFC_0004)
    );
    let mut s = vscr(true);
    assert_eq!(
        vmsumuhs(&mut s, splat(0xFFFF_FFFF), splat(0xFFFF_FFFF), splat(2)),
        splat(u32::MAX)
    );
    assert!(s.sat());
    // 0x8000 × 0x8000 twice is 2^31, one past the largest signed word.
    let mut s = vscr(true);
    let r = vmsumshs(&mut s, splat(0x8000_8000), splat(0x8000_8000), splat(0));
    assert_eq!(r, splat(0x7FFF_FFFF));
    assert!(s.sat());
    assert_eq!(
        vmsumshm(splat(0x8000_8000), splat(0x8000_8000), splat(0)),
        splat(0x8000_0000)
    );
    let mut s = vscr(true);
    assert_eq!(
        vmsumshs(
            &mut s,
            splat(0xFFFF_0002),
            splat(0x0003_0004),
            splat(u32::MAX)
        ),
        splat(4),
        "-3 + 8 - 1"
    );
    assert!(!s.sat());
}

#[test]
fn sums_across_saturate_into_their_words() {
    let mut s = vscr(true);
    let r = vsumsws(&mut s, v(0x7FFF_FFFF, 1, 0, 0), v(9, 9, 9, 0));
    assert_eq!(r, v(0, 0, 0, 0x7FFF_FFFF));
    assert!(s.sat());
    let mut s = vscr(true);
    assert_eq!(
        vsumsws(&mut s, v(1, 2, 3, u32::MAX), v(9, 9, 9, 10)),
        v(0, 0, 0, 15)
    );
    assert!(!s.sat());
    let mut s = vscr(true);
    let r = vsum2sws(&mut s, v(1, 2, 0x8000_0000, u32::MAX), v(9, 3, 9, 0));
    assert_eq!(r, v(0, 6, 0, 0x8000_0000));
    assert!(s.sat());
    let mut s = vscr(true);
    let r = vsum4ubs(
        &mut s,
        v(0x0102_0304, 0xFFFF_FFFF, 0, 0),
        v(5, u32::MAX, 0, 1),
    );
    assert_eq!(r, v(15, u32::MAX, 0, 1));
    assert!(s.sat());
    let mut s = vscr(true);
    let r = vsum4sbs(&mut s, v(0xFF02_FD04, 0x8080_8080, 0, 0), v(5, 0, 0, 0));
    assert_eq!(r, v(7, (-512i32) as u32, 0, 0));
    assert!(!s.sat());
    let r = vsum4shs(
        &mut s,
        v(0xFFFF_0002, 0x7FFF_7FFF, 0, 0),
        v(0, 0x7FFF_FFFF, 0, 0),
    );
    assert_eq!(r, v(1, 0x7FFF_FFFF, 0, 0));
    assert!(s.sat());
}

#[test]
fn integer_compares_give_all_ones_or_zeros() {
    let a = v(0x8001_8000, 0x0000_0001, 0x8000_0000, 7);
    let b = v(0x0101_0001, 0x0000_0001, 0x0000_0001, 7);
    assert_eq!(
        vcmpequb(a, b),
        v(0x00FF_0000, u32::MAX, 0x00FF_FF00, u32::MAX)
    );
    assert_eq!(vcmpequh(a, b), v(0, u32::MAX, 0x0000_0000, u32::MAX));
    assert_eq!(vcmpequw(a, b), v(0, u32::MAX, 0, u32::MAX));
    assert_eq!(vcmpgtub(a, b), v(0xFF00_FF00, 0, 0xFF00_0000, 0));
    assert_eq!(vcmpgtsb(a, b), v(0, 0, 0, 0));
    assert_eq!(vcmpgtuh(a, b), v(0xFFFF_FFFF, 0, 0xFFFF_0000, 0));
    assert_eq!(vcmpgtsh(a, b), v(0, 0, 0, 0));
    assert_eq!(vcmpgtuw(a, b), v(u32::MAX, 0, u32::MAX, 0));
    assert_eq!(vcmpgtsw(a, b), v(0, 0, 0, 0));
}
