// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The floating-point helpers at the edges. Expected values come from Book I, chapter 4, worked
//! out by hand; the comments say how. Rounded values were checked with exact rational arithmetic.

use super::*;

fn f(bits: u64) -> f64 {
    f64::from_bits(bits)
}

/// Runs `op` on a clear FPSCR and returns the bits of the result and the FPSCR after it.
fn run(op: impl FnOnce(&mut Fpscr) -> f64) -> (u64, u32) {
    let mut fpscr = Fpscr::default();
    let result = op(&mut fpscr);
    (result.to_bits(), fpscr.to_u32())
}

const POS_ZERO: u64 = 0;
const NEG_ZERO: u64 = 0x8000_0000_0000_0000;
const ONE: u64 = 0x3FF0_0000_0000_0000;
const INF: u64 = 0x7FF0_0000_0000_0000;
const NEG_INF: u64 = 0xFFF0_0000_0000_0000;
/// The smallest positive denormal.
const DENORMAL: u64 = 1;
/// A quiet NaN with payload 0xAA.
const QNAN_A: u64 = 0x7FF8_0000_0000_00AA;
/// A quiet NaN with payload 0xBB.
const QNAN_B: u64 = 0x7FF8_0000_0000_00BB;
/// A signaling NaN with payload 0xBB, and the quiet NaN it becomes.
const SNAN_B: u64 = 0x7FF0_0000_0000_00BB;
const SNAN_B_QUIETED: u64 = 0x7FF8_0000_0000_00BB;
/// A quiet NaN with payload 0xCC.
const QNAN_C: u64 = 0x7FF8_0000_0000_00CC;
/// A negative signaling NaN, and the quiet NaN it becomes: the sign stays.
const NEG_SNAN: u64 = 0xFFF0_0000_0000_00CC;
const NEG_SNAN_QUIETED: u64 = 0xFFF8_0000_0000_00CC;

/// FX and VX with the invalid-operation bit `bit`: what a first invalid operation leaves.
const fn invalid(bit: u32) -> u32 {
    Fpscr::FX | Fpscr::VX | bit
}

#[test]
fn moves_change_only_the_sign_bit() {
    assert_eq!(fneg(f(POS_ZERO)).to_bits(), NEG_ZERO);
    assert_eq!(fneg(f(NEG_ZERO)).to_bits(), POS_ZERO);
    // A signaling NaN keeps its payload and stays signaling (4.6.4).
    assert_eq!(fneg(f(SNAN_B)).to_bits(), 0xFFF0_0000_0000_00BB);
    assert_eq!(fabs(f(NEG_SNAN)).to_bits(), 0x7FF0_0000_0000_00CC);
    assert_eq!(fabs(f(NEG_INF)).to_bits(), INF);
    assert_eq!(fnabs(f(ONE)).to_bits(), 0xBFF0_0000_0000_0000);
    assert_eq!(fnabs(f(QNAN_A)).to_bits(), 0xFFF8_0000_0000_00AA);
    assert_eq!(fnabs(f(DENORMAL)).to_bits(), 0x8000_0000_0000_0001);
}

#[test]
fn fsel_selects_c_from_zero_up_and_b_otherwise() {
    let (c, b) = (f(SNAN_B), f(QNAN_C));
    let select = |a: u64| fsel(f(a), c, b).to_bits();
    // ±0 compare equal to zero (5.2.2), so -0 selects frC.
    assert_eq!(select(NEG_ZERO), SNAN_B, "-0");
    assert_eq!(select(POS_ZERO), SNAN_B, "+0");
    assert_eq!(select(INF), SNAN_B, "+inf");
    assert_eq!(select(DENORMAL), SNAN_B, "+denormal");
    assert_eq!(select(0x8000_0000_0000_0001), QNAN_C, "-denormal");
    assert_eq!(select(NEG_INF), QNAN_C, "-inf");
    assert_eq!(select(QNAN_A), QNAN_C, "a NaN selects frB");
}

#[test]
fn a_nan_operand_wins_in_the_order_a_b_c() {
    // Both NaNs: frA wins, quiet already; frB being signaling still sets VXSNAN.
    assert_eq!(
        run(|s| fadd(s, f(QNAN_A), f(SNAN_B))),
        (QNAN_A, invalid(Fpscr::VXSNAN))
    );
    // A signaling NaN comes back quiet, with its payload.
    assert_eq!(
        run(|s| fsub(s, f(ONE), f(SNAN_B))),
        (SNAN_B_QUIETED, invalid(Fpscr::VXSNAN))
    );
    assert_eq!(run(|s| fmul(s, f(ONE), f(QNAN_C))), (QNAN_C, 0));
    assert_eq!(run(|s| fdiv(s, f(QNAN_B), f(POS_ZERO))), (QNAN_B, 0));
    assert_eq!(run(|s| fsqrt(s, f(QNAN_B))), (QNAN_B, 0));
    // In fmadd frT, frA, frC, frB, frB (the addend) comes before frC (the second factor).
    assert_eq!(run(|s| fmadd(s, f(ONE), f(QNAN_C), f(QNAN_B))), (QNAN_B, 0));
    assert_eq!(
        run(|s| fmadd(s, f(QNAN_A), f(QNAN_C), f(QNAN_B))),
        (QNAN_A, 0)
    );
    assert_eq!(run(|s| fmsub(s, f(ONE), f(QNAN_C), f(ONE))), (QNAN_C, 0));
    // The negative signaling NaN keeps its sign when quieted.
    assert_eq!(
        run(|s| fmul(s, f(NEG_SNAN), f(ONE))),
        (NEG_SNAN_QUIETED, invalid(Fpscr::VXSNAN))
    );
}

#[test]
fn invalid_operations_generate_the_positive_default_nan() {
    assert_eq!(DEFAULT_NAN, 0x7FF8_0000_0000_0000);
    let nan = DEFAULT_NAN;
    assert_eq!(
        run(|s| fadd(s, f(INF), f(NEG_INF))),
        (nan, invalid(Fpscr::VXISI))
    );
    assert_eq!(
        run(|s| fsub(s, f(NEG_INF), f(NEG_INF))),
        (nan, invalid(Fpscr::VXISI))
    );
    assert_eq!(
        run(|s| fmul(s, f(NEG_ZERO), f(INF))),
        (nan, invalid(Fpscr::VXIMZ))
    );
    assert_eq!(
        run(|s| fdiv(s, f(POS_ZERO), f(NEG_ZERO))),
        (nan, invalid(Fpscr::VXZDZ))
    );
    assert_eq!(
        run(|s| fdiv(s, f(NEG_INF), f(INF))),
        (nan, invalid(Fpscr::VXIDI))
    );
    assert_eq!(
        run(|s| fsqrt(s, f(0xBFF0_0000_0000_0000))),
        (nan, invalid(Fpscr::VXSQRT))
    );
    assert_eq!(run(|s| fsqrt(s, f(NEG_INF))), (nan, invalid(Fpscr::VXSQRT)));
}

#[test]
fn signs_of_zero_follow_4_3_3() {
    assert_eq!(run(|s| fsqrt(s, f(NEG_ZERO))), (NEG_ZERO, 0));
    assert_eq!(run(|s| fadd(s, f(NEG_ZERO), f(NEG_ZERO))), (NEG_ZERO, 0));
    assert_eq!(run(|s| fadd(s, f(NEG_ZERO), f(POS_ZERO))), (POS_ZERO, 0));
    assert_eq!(run(|s| fsub(s, f(ONE), f(ONE))), (POS_ZERO, 0));
    assert_eq!(
        run(|s| fmul(s, f(NEG_ZERO), f(0x4014_0000_0000_0000))),
        (NEG_ZERO, 0)
    );
}

#[test]
fn a_number_over_zero_is_an_infinity_and_a_zero_divide() {
    let zx = Fpscr::FX | Fpscr::ZX;
    assert_eq!(run(|s| fdiv(s, f(ONE), f(POS_ZERO))), (INF, zx));
    assert_eq!(run(|s| fdiv(s, f(ONE), f(NEG_ZERO))), (NEG_INF, zx));
    assert_eq!(run(|s| fdiv(s, f(DENORMAL), f(NEG_ZERO))), (NEG_INF, zx));
    // Infinity over zero is exact: no exception (4.4.2.1).
    assert_eq!(run(|s| fdiv(s, f(INF), f(POS_ZERO))), (INF, 0));
}

#[test]
fn multiply_add_rounds_once() {
    // a = c = 1 + 2^-30: a × c = 1 + 2^-29 + 2^-60 exactly. Rounded to double first, the 2^-60 is
    // lost (half an ulp of 1 is 2^-53), and adding -(1 + 2^-29) gives 0; fused, 2^-60 remains.
    let a = f(0x3FF0_0000_0040_0000);
    let b = f(0x3FF0_0000_0080_0000);
    let two_to_minus_60 = 0x3C30_0000_0000_0000;
    assert_eq!(run(|s| fmadd(s, a, a, fneg(b))), (two_to_minus_60, 0));
    assert_eq!(run(|s| fmsub(s, a, a, b)), (two_to_minus_60, 0));
    assert_eq!(
        run(|s| fnmadd(s, a, a, fneg(b))),
        (two_to_minus_60 | NEG_ZERO, 0)
    );
    assert_eq!(run(|s| fnmsub(s, a, a, b)), (two_to_minus_60 | NEG_ZERO, 0));
    // 1 × 1 + 1 = 2, negated after the rounding.
    assert_eq!(
        run(|s| fnmadd(s, f(ONE), f(ONE), f(ONE))),
        (0xC000_0000_0000_0000, 0)
    );
}

#[test]
fn negative_multiply_add_does_not_negate_a_nan() {
    // A quiet NaN keeps its sign; a signaling one keeps its sign when quieted; a generated one is
    // positive (4.6.5.2, fnmadd).
    assert_eq!(run(|s| fnmadd(s, f(QNAN_A), f(ONE), f(ONE))), (QNAN_A, 0));
    assert_eq!(
        run(|s| fnmsub(s, f(ONE), f(ONE), f(NEG_SNAN))),
        (NEG_SNAN_QUIETED, invalid(Fpscr::VXSNAN))
    );
    assert_eq!(
        run(|s| fnmadd(s, f(POS_ZERO), f(INF), f(ONE))),
        (DEFAULT_NAN, invalid(Fpscr::VXIMZ))
    );
}

#[test]
fn multiply_add_exceptions_are_those_of_a_multiply_then_an_add() {
    // 0 × inf with a quiet NaN addend: the NaN is the result, and VXIMZ is still set.
    assert_eq!(
        run(|s| fmadd(s, f(POS_ZERO), f(INF), f(QNAN_B))),
        (QNAN_B, invalid(Fpscr::VXIMZ))
    );
    // With a signaling addend, both VXSNAN and VXIMZ (4.4).
    assert_eq!(
        run(|s| fmadd(s, f(INF), f(POS_ZERO), f(SNAN_B))),
        (SNAN_B_QUIETED, invalid(Fpscr::VXSNAN | Fpscr::VXIMZ))
    );
    // inf × 1 + (-inf) and inf × 1 - inf are magnitude subtractions of infinities.
    assert_eq!(
        run(|s| fmadd(s, f(INF), f(ONE), f(NEG_INF))),
        (DEFAULT_NAN, invalid(Fpscr::VXISI))
    );
    assert_eq!(
        run(|s| fmsub(s, f(INF), f(ONE), f(INF))),
        (DEFAULT_NAN, invalid(Fpscr::VXISI))
    );
    // inf × 1 + inf is exact.
    assert_eq!(run(|s| fmadd(s, f(INF), f(ONE), f(INF))), (INF, 0));
}

#[test]
fn single_forms_round_the_exact_result_once() {
    // 1 + 2^-24 is the midpoint between 1 and 1 + 2^-23: a tie, to even, gives 1.
    let tie = f(0x3E70_0000_0000_0000); // 2^-24
    assert_eq!(run(|s| fadds(s, f(ONE), tie)), (ONE, 0));
    // 1 + 2^-24 + 2^-47 is above that midpoint: 1 + 2^-23. Unrounded it would be
    // 0x3FF0_0000_1000_0020.
    let above = f(0x3E70_0000_2000_0000); // 2^-24 × (1 + 2^-23), a single
    assert_eq!(run(|s| fadds(s, f(ONE), above)), (0x3FF0_0000_2000_0000, 0));
    assert_eq!(
        run(|s| fsubs(s, f(ONE), fneg(above))),
        (0x3FF0_0000_2000_0000, 0)
    );
    // (1 + 2^-12)^2 = 1 + 2^-11 + 2^-24, a midpoint whose lower neighbor 1 + 2^-11 is even.
    let a = f(0x3FF0_0100_0000_0000);
    assert_eq!(run(|s| fmuls(s, a, a)), (0x3FF0_0200_0000_0000, 0));
    // 1/3 and sqrt(2) rounded to single: 0x3EAAAAAB and 0x3FB504F3, widened.
    let three = f(0x4008_0000_0000_0000);
    assert_eq!(run(|s| fdivs(s, f(ONE), three)), (0x3FD5_5555_6000_0000, 0));
    let two = f(0x4000_0000_0000_0000);
    assert_eq!(run(|s| fsqrts(s, two)), (0x3FF6_A09E_6000_0000, 0));
}

#[test]
fn single_forms_overflow_and_underflow_in_single_range() {
    // 2^127 × 4 = 2^129 is past the largest single: an infinity in round to nearest (4.4.3.2).
    let two_127 = f(0x47E0_0000_0000_0000);
    let four = f(0x4010_0000_0000_0000);
    assert_eq!(run(|s| fmuls(s, two_127, four)), (INF, 0));
    // 2^-126 × 2^-10 = 2^-136, a single denormal, exact.
    let (two_126, two_10) = (f(0x3810_0000_0000_0000), f(0x3F50_0000_0000_0000));
    assert_eq!(
        run(|s| fmuls(s, two_126, two_10)),
        (0x3770_0000_0000_0000, 0)
    );
    // 1.5 × 2^-140 × 2^-10 = 0.75 × 2^-149, nearer 2^-149 than 0.
    let a = f(0x3738_0000_0000_0000); // 1.5 × 2^-140
    assert_eq!(run(|s| fmuls(s, a, two_10)), (0x36A0_0000_0000_0000, 0));
    // 2^-140 × 2^-10 = 2^-150, halfway between 0 and 2^-149: to even, 0.
    let b = f(0x3730_0000_0000_0000); // 2^-140
    assert_eq!(run(|s| fmuls(s, b, two_10)), (POS_ZERO, 0));
}

#[test]
fn single_forms_keep_the_first_35_bits_of_a_nan() {
    // A single signaling NaN (low 29 bits zero), quieted.
    let snan = f(0x7FF0_0000_2000_0000);
    assert_eq!(
        run(|s| fadds(s, snan, f(ONE))),
        (0x7FF8_0000_2000_0000, invalid(Fpscr::VXSNAN))
    );
    assert_eq!(
        run(|s| fmuls(s, f(INF), f(POS_ZERO))),
        (DEFAULT_NAN, invalid(Fpscr::VXIMZ))
    );
}

#[test]
fn fused_single_forms_do_not_round_twice() {
    // a = c = 1 + 2^-12: a × c = 1 + 2^-11 + 2^-24, the midpoint between the singles 1 + 2^-11
    // (even) and 1 + 2^-11 + 2^-23. Adding 2^-80 puts the exact sum above the midpoint, so it
    // rounds up. A double fma loses the 2^-80 and lands on the midpoint, which ties to even (down).
    let a = f(0x3FF0_0100_0000_0000);
    let tiny = f(0x3AF0_0000_0000_0000); // 2^-80
    let up = 0x3FF0_0200_2000_0000; // 1 + 2^-11 + 2^-23
    assert_eq!(run(|s| fmadds(s, a, a, tiny)), (up, 0));
    assert_eq!(run(|s| fmsubs(s, a, a, fneg(tiny))), (up, 0));
    assert_eq!(run(|s| fnmadds(s, a, a, tiny)), (up | NEG_ZERO, 0));
    // A negative product, away from zero: -(midpoint + 2^-80) rounds to -(1 + 2^-11 + 2^-23).
    assert_eq!(
        run(|s| fmadds(s, fneg(a), a, fneg(tiny))),
        (up | NEG_ZERO, 0)
    );
    assert_eq!(run(|s| fnmsubs(s, a, a, fneg(tiny))), (up | NEG_ZERO, 0));
    // (1 + 2^-12)(1 + 3 × 2^-12) = 1 + 2^-10 + 3 × 2^-24, the midpoint between 1 + 2^-10 + 2^-23
    // (odd) and 1 + 2^-10 + 2^-22 (even). Subtracting 2^-80 puts the sum below it, so it rounds
    // down, toward zero; a double fma would tie to the even single above.
    let c = f(0x3FF0_0300_0000_0000);
    let down = 0x3FF0_0400_2000_0000; // 1 + 2^-10 + 2^-23
    assert_eq!(run(|s| fmadds(s, a, c, fneg(tiny))), (down, 0));
    assert_eq!(run(|s| fmsubs(s, a, c, tiny)), (down, 0));
    // The suite's case: 9999.99 is not a single, so the ISA leaves the result undefined; this is
    // the double result rounded, 100009800.
    let x = f(0x40C3_87FE_B851_EB85);
    assert_eq!(run(|s| fmadds(s, x, x, x)).0, 100_009_800.0f64.to_bits());
}

#[test]
fn frsp_rounds_to_nearest_single() {
    // 1 + 2^-24 ties to 1; one double ulp more rounds up.
    assert_eq!(run(|s| frsp(s, f(0x3FF0_0000_1000_0000))), (ONE, 0));
    assert_eq!(
        run(|s| frsp(s, f(0x3FF0_0000_1000_0001))),
        (0x3FF0_0000_2000_0000, 0)
    );
    // 2^128 overflows single: +inf, and -inf for -2^128.
    assert_eq!(run(|s| frsp(s, f(0x47F0_0000_0000_0000))), (INF, 0));
    assert_eq!(run(|s| frsp(s, f(0xC7F0_0000_0000_0000))), (NEG_INF, 0));
    assert_eq!(run(|s| frsp(s, f(NEG_ZERO))), (NEG_ZERO, 0));
    // A double denormal is far below single range; 2^-150 ties to 0; 2^-150 × (1 + 2^-50) rounds
    // to the smallest single denormal, 2^-149.
    assert_eq!(run(|s| frsp(s, f(DENORMAL))), (POS_ZERO, 0));
    assert_eq!(run(|s| frsp(s, f(0x3690_0000_0000_0000))), (POS_ZERO, 0));
    assert_eq!(
        run(|s| frsp(s, f(0x3690_0000_0000_0004))),
        (0x36A0_0000_0000_0000, 0)
    );
    // NaNs keep bits 0:34, quieted (4.3.2): the low 29 bits of the payload go.
    assert_eq!(
        run(|s| frsp(s, f(0x7FF0_0000_0000_0001))),
        (DEFAULT_NAN, invalid(Fpscr::VXSNAN))
    );
    assert_eq!(
        run(|s| frsp(s, f(0x7FF8_0000_FFFF_FFFF))),
        (0x7FF8_0000_E000_0000, 0)
    );
}

#[test]
fn fctiwz_truncates_and_saturates() {
    let word = |bits: u64| run(|s| fctiwz(s, f(bits)));
    let cvi = invalid(Fpscr::VXCVI);
    assert_eq!(word(POS_ZERO), (0, 0));
    assert_eq!(word(NEG_ZERO), (0, 0));
    assert_eq!(word(DENORMAL), (0, 0));
    assert_eq!(word(0x4007_3333_3333_3333), (2, 0), "2.9");
    // Negative words are sign-extended into the high word, as the suite expects.
    assert_eq!(word(0xC007_3333_3333_3333), (u64::MAX - 1, 0), "-2.9");
    assert_eq!(word(0xBFF0_0000_0000_0000), (u64::MAX, 0), "-1");
    assert_eq!(
        word(0xC1E0_0000_0000_0000),
        (0xFFFF_FFFF_8000_0000, 0),
        "-2^31"
    );
    assert_eq!(word(0x41DF_FFFF_FFC0_0000), (0x7FFF_FFFF, 0), "2^31 - 1");
    // 2^31 - 0.5 truncates into range; 2^31 does not.
    assert_eq!(word(0x41DF_FFFF_FFE0_0000), (0x7FFF_FFFF, 0), "2^31 - 0.5");
    assert_eq!(word(0x41E0_0000_0000_0000), (0x7FFF_FFFF, cvi), "2^31");
    // -2^31 - 0.9 truncates to -2^31, in range; -2^31 - 1 does not.
    assert_eq!(
        word(0xC1E0_0000_001C_CCCD),
        (0xFFFF_FFFF_8000_0000, 0),
        "-2^31 - 0.9"
    );
    assert_eq!(
        word(0xC1E0_0000_0020_0000),
        (0xFFFF_FFFF_8000_0000, cvi),
        "-2^31 - 1"
    );
    assert_eq!(word(INF), (0x7FFF_FFFF, cvi));
    assert_eq!(word(NEG_INF), (0xFFFF_FFFF_8000_0000, cvi));
    // A NaN gives the smallest word (4.4.1.2), not the 0 of an `as` cast.
    assert_eq!(word(QNAN_A), (0xFFFF_FFFF_8000_0000, cvi));
    assert_eq!(
        word(SNAN_B),
        (0xFFFF_FFFF_8000_0000, invalid(Fpscr::VXCVI | Fpscr::VXSNAN))
    );
}

#[test]
fn fctiw_rounds_to_nearest_even() {
    let word = |x: f64| run(|s| fctiw(s, x));
    assert_eq!(word(0.5), (0, 0));
    assert_eq!(word(1.5), (2, 0));
    assert_eq!(word(2.5), (2, 0));
    assert_eq!(word(-0.5), (0, 0), "-0.5 rounds to -0, the integer 0");
    assert_eq!(word(-1.5), (u64::MAX - 1, 0));
    // 2^31 - 0.5 ties to the even 2^31, which is out of range (Appendix A.2 rounds first).
    assert_eq!(word(2_147_483_647.5), (0x7FFF_FFFF, invalid(Fpscr::VXCVI)));
    // -2^31 - 0.5 ties to the even -2^31, in range.
    assert_eq!(word(-2_147_483_648.5), (0xFFFF_FFFF_8000_0000, 0));
    assert_eq!(
        word(-2_147_483_649.5),
        (0xFFFF_FFFF_8000_0000, invalid(Fpscr::VXCVI))
    );
}

#[test]
fn fctid_and_fctidz_saturate_at_64_bits() {
    let cvi = invalid(Fpscr::VXCVI);
    let z = |bits: u64| run(|s| fctidz(s, f(bits)));
    assert_eq!(
        z(0x43E0_0000_0000_0000),
        (0x7FFF_FFFF_FFFF_FFFF, cvi),
        "2^63"
    );
    assert_eq!(
        z(0xC3E0_0000_0000_0000),
        (0x8000_0000_0000_0000, 0),
        "-2^63"
    );
    // The largest double below 2^63 is 2^63 - 1024.
    assert_eq!(z(0x43DF_FFFF_FFFF_FFFF), (0x7FFF_FFFF_FFFF_FC00, 0));
    assert_eq!(z(0xBFF8_0000_0000_0000), (u64::MAX, 0), "-1.5");
    assert_eq!(z(NEG_INF), (0x8000_0000_0000_0000, cvi));
    assert_eq!(z(QNAN_A), (0x8000_0000_0000_0000, cvi));
    let nearest = |x: f64| run(|s| fctid(s, x));
    assert_eq!(nearest(2.5), (2, 0));
    assert_eq!(nearest(3.5), (4, 0));
    assert_eq!(nearest(-3.5), (u64::MAX - 3, 0));
    assert_eq!(nearest(1e300), (0x7FFF_FFFF_FFFF_FFFF, cvi));
}

#[test]
fn fcfid_rounds_the_integer_once() {
    let float = |value: i64| fcfid(f(value as u64)).to_bits();
    assert_eq!(float(0), POS_ZERO);
    assert_eq!(float(-1), 0xBFF0_0000_0000_0000);
    assert_eq!(float(i64::MIN), 0xC3E0_0000_0000_0000, "-2^63, exact");
    // 2^63 - 1 needs 63 bits: it rounds up to 2^63.
    assert_eq!(float(i64::MAX), 0x43E0_0000_0000_0000);
    // Above 2^53 doubles step by 2. 2^53 + 1 ties to 2^53 (even significand); 2^53 + 3 ties to
    // 2^53 + 4, whose significand is even, not to 2^53 + 2.
    assert_eq!(float((1 << 53) + 1), 0x4340_0000_0000_0000);
    assert_eq!(float((1 << 53) + 3), 0x4340_0000_0000_0002);
    // A value whose halves carry into each other: -2^32 + 5.
    assert_eq!(fcfid(f((-(1i64 << 32) + 5) as u64)), -4_294_967_291.0);
}

#[test]
fn lfs_converts_bit_for_bit() {
    let load = |word: u32| single_to_double(word).to_bits();
    assert_eq!(load(0x3F80_0000), ONE);
    assert_eq!(load(0x8000_0000), NEG_ZERO);
    // The smallest single denormal, 2^-149, and the largest, 2^-126 × (1 - 2^-23), become
    // normal doubles.
    assert_eq!(load(0x0000_0001), 0x36A0_0000_0000_0000);
    assert_eq!(load(0x007F_FFFF), 0x380F_FFFF_C000_0000);
    assert_eq!(load(0x7F80_0000), INF);
    assert_eq!(load(0xFF80_0000), NEG_INF);
    assert_eq!(load(0x7FC0_0000), DEFAULT_NAN);
    // A signaling NaN stays signaling: the fraction moves up 29 bits, the quiet bit stays clear.
    assert_eq!(load(0x7F80_0001), 0x7FF0_0000_2000_0000);
    assert_eq!(load(0xFFA0_0000), 0xFFF4_0000_0000_0000);
}

#[test]
fn stfs_selects_bits_without_rounding() {
    let store = |bits: u64| double_to_single(f(bits));
    assert_eq!(store(ONE), 0x3F80_0000);
    assert_eq!(store(NEG_ZERO), 0x8000_0000);
    assert_eq!(store(INF), 0x7F80_0000);
    assert_eq!(store(DEFAULT_NAN), 0x7FC0_0000);
    // Bits 5:34 of the fraction: a signaling NaN stays signaling, and one whose payload lies in
    // the low 29 bits comes out as an infinity, as the ISA's formula says.
    assert_eq!(store(0x7FF0_0000_2000_0000), 0x7F80_0001);
    assert_eq!(store(0x7FF0_0000_0000_0001), 0x7F80_0000);
    // 1 + 2^-24 + 2^-52 is above the midpoint, but stfs truncates: 1.0, not 0x3F800001.
    assert_eq!(store(0x3FF0_0000_1000_0001), 0x3F80_0000);
    // 2^200 is past single range: bits 0:1 (0b01) and 5:34 of 0x4C70_0000_0000_0000.
    assert_eq!(store(0x4C70_0000_0000_0000), 0x6380_0000);
    // Single denormals: 2^-127 (biased 896) is 2^-126 × 0.5, fraction bit 22; 2^-149 (biased
    // 874) is 1; and
    // 1.5 × 2^-149 truncates to 1.
    assert_eq!(store(0x3800_0000_0000_0000), 0x0040_0000);
    assert_eq!(store(0x36A0_0000_0000_0000), 0x0000_0001);
    assert_eq!(store(0x36A8_0000_0000_0000), 0x0000_0001);
    // Below that range (undefined), a zero of the same sign; a double denormal too.
    assert_eq!(store(0x3690_0000_0000_0000), 0);
    assert_eq!(store(0xB690_0000_0000_0000), 0x8000_0000);
    assert_eq!(store(0x8000_0000_0000_0001), 0x8000_0000);
}

#[test]
fn estimates_are_exact_with_the_special_values_of_5_2_1() {
    let zx = Fpscr::FX | Fpscr::ZX;
    assert_eq!(run(|s| fres(s, 2.0)), (0x3FE0_0000_0000_0000, 0));
    assert_eq!(
        run(|s| fres(s, 3.0)),
        (0x3FD5_5555_6000_0000, 0),
        "1/3 single"
    );
    assert_eq!(run(|s| fres(s, f(POS_ZERO))), (INF, zx));
    assert_eq!(run(|s| fres(s, f(NEG_ZERO))), (NEG_INF, zx));
    assert_eq!(run(|s| fres(s, f(INF))), (POS_ZERO, 0));
    assert_eq!(run(|s| fres(s, f(NEG_INF))), (NEG_ZERO, 0));
    assert_eq!(
        run(|s| fres(s, f(0x7FF0_0000_2000_0000))),
        (0x7FF8_0000_2000_0000, invalid(Fpscr::VXSNAN))
    );
    assert_eq!(run(|s| frsqrte(s, 4.0)), (0x3FE0_0000_0000_0000, 0));
    assert_eq!(run(|s| frsqrte(s, f(POS_ZERO))), (INF, zx));
    assert_eq!(run(|s| frsqrte(s, f(NEG_ZERO))), (NEG_INF, zx));
    assert_eq!(run(|s| frsqrte(s, f(INF))), (POS_ZERO, 0));
    assert_eq!(
        run(|s| frsqrte(s, -1.0)),
        (DEFAULT_NAN, invalid(Fpscr::VXSQRT))
    );
    assert_eq!(
        run(|s| frsqrte(s, f(NEG_INF))),
        (DEFAULT_NAN, invalid(Fpscr::VXSQRT))
    );
    assert_eq!(run(|s| frsqrte(s, f(QNAN_A))), (QNAN_A, 0));
}

#[test]
fn exceptions_accumulate_and_fx_follows_new_ones() {
    let mut fpscr = Fpscr::default();
    fdiv(&mut fpscr, 1.0, 0.0);
    fmul(&mut fpscr, 0.0, f64::INFINITY);
    assert_eq!(
        fpscr.to_u32(),
        Fpscr::FX | Fpscr::ZX | Fpscr::VX | Fpscr::VXIMZ
    );
    // Clearing FX, then repeating an exception already set, leaves FX clear.
    fpscr.mtfsb0(0);
    fmul(&mut fpscr, 0.0, f64::INFINITY);
    assert_eq!(fpscr.to_u32() & Fpscr::FX, 0);
}
