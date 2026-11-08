// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::{splat, v, vscr};
use crate::ops::*;
use crate::{V128, Vscr};

const ONE: u32 = 0x3F80_0000;
const TWO: u32 = 0x4000_0000;
const THREE: u32 = 0x4040_0000;
const HALF: u32 = 0x3F00_0000;
const NEG_ZERO: u32 = 0x8000_0000;
const INF: u32 = 0x7F80_0000;
const NEG_INF: u32 = 0xFF80_0000;
const QNAN_A: u32 = 0x7FC0_00AA;
const QNAN_B: u32 = 0x7FC0_00BB;
const QNAN_C: u32 = 0xFFC0_00CC;
/// A signaling NaN with payload 0xBB; quieted it is `0x7FC000BB`.
const SNAN_B: u32 = 0x7F80_00BB;
/// The smallest positive denormal, 2^-149.
const DENORMAL: u32 = 0x0000_0001;
/// 2^-126, the smallest normal.
const MIN_NORMAL: u32 = 0x0080_0000;

#[test]
fn addition_and_subtraction_round_once_in_every_lane() {
    let nj = vscr(true);
    // 1 + 2, -2 + 2 (+0 in round to nearest), 0.5 + 0.25, 3 + -3.
    let a = v(ONE, 0xC000_0000, HALF, THREE);
    let b = v(TWO, TWO, 0x3E80_0000, 0xC040_0000);
    assert_eq!(vaddfp(nj, a, b), v(THREE, 0, 0x3F40_0000, 0));
    // 1 + 2^-24 is a tie that rounds to the even 1; one more unit of 2^-47 rounds up.
    let tie = 0x3380_0000;
    assert_eq!(vaddfp(nj, splat(ONE), splat(tie)), splat(ONE));
    assert_eq!(vsubfp(nj, splat(ONE), splat(tie | NEG_ZERO)), splat(ONE));
    assert_eq!(
        vaddfp(nj, splat(0x3F80_0001), splat(tie)),
        splat(0x3F80_0002),
        "a tie from an odd significand rounds up to even"
    );
    assert_eq!(vsubfp(nj, splat(ONE), splat(ONE)), splat(0), "+0");
    assert_eq!(
        vaddfp(nj, splat(NEG_ZERO), splat(NEG_ZERO)),
        splat(NEG_ZERO)
    );
    assert_eq!(
        vaddfp(nj, splat(0x7F7F_FFFF), splat(0x7F7F_FFFF)),
        splat(INF)
    );
}

#[test]
fn non_java_mode_flushes_denormal_inputs_to_zeros_of_their_sign() {
    let a = v(DENORMAL, DENORMAL | NEG_ZERO, 0x007F_FFFF, ONE);
    let b = v(0, NEG_ZERO, 0x007F_FFFF, DENORMAL);
    assert_eq!(vaddfp(vscr(true), a, b), v(0, NEG_ZERO, 0, ONE));
    assert_eq!(
        vaddfp(vscr(false), a, b),
        v(DENORMAL, DENORMAL | NEG_ZERO, 0x00FF_FFFE, ONE),
        "Java mode keeps them"
    );
}

#[test]
fn non_java_mode_flushes_tiny_results_before_rounding() {
    // 1.5 × 2^-126 - 2^-126 = 2^-127, a denormal; the sign of the zero is that of the result.
    let a = v(0x00C0_0000, 0x80C0_0000, 0, 0);
    let b = v(MIN_NORMAL, 0x8080_0000, 0, 0);
    assert_eq!(vsubfp(vscr(true), a, b), v(0, NEG_ZERO, 0, 0));
    assert_eq!(vsubfp(vscr(false), a, b), v(0x0040_0000, 0x8040_0000, 0, 0));
    // (1 - 2^-24) × 2^-126 = 2^-126 - 2^-150 is below the normal range, though it rounds to
    // 2^-126 (a tie between 0x007FFFFF and the even 0x00800000): underflow is detected before
    // rounding, so non-Java mode flushes it.
    let below = 0x3F7F_FFFF;
    assert_eq!(
        vmulfp128(vscr(true), splat(below), splat(MIN_NORMAL)),
        splat(0)
    );
    assert_eq!(
        vmulfp128(vscr(false), splat(below), splat(MIN_NORMAL)),
        splat(MIN_NORMAL)
    );
    assert_eq!(
        vmaddfp(vscr(true), splat(below), splat(MIN_NORMAL), splat(0)),
        splat(0)
    );
    assert_eq!(
        vmaddfp(
            vscr(true),
            splat(below | NEG_ZERO),
            splat(MIN_NORMAL),
            splat(0)
        ),
        splat(NEG_ZERO)
    );
}

#[test]
fn a_nan_result_is_the_first_nan_operand_quieted() {
    let nj = vscr(true);
    let a = v(QNAN_A, ONE, SNAN_B, 0xFF80_0002);
    let b = v(QNAN_B, SNAN_B, QNAN_B, QNAN_B);
    // vA first; a signaling NaN gets the quiet bit and keeps its sign and payload.
    assert_eq!(
        vaddfp(nj, a, b),
        v(QNAN_A, 0x7FC0_00BB, 0x7FC0_00BB, 0xFFC0_0002)
    );
    // Invalid operations generate the default NaN.
    assert_eq!(
        vaddfp(nj, splat(INF), splat(NEG_INF)),
        splat(VECTOR_DEFAULT_NAN)
    );
    assert_eq!(
        vsubfp(nj, splat(INF), splat(INF)),
        splat(VECTOR_DEFAULT_NAN)
    );
    assert_eq!(
        vmulfp128(nj, splat(INF), splat(0)),
        splat(VECTOR_DEFAULT_NAN)
    );
    assert_eq!(VECTOR_DEFAULT_NAN, 0x7FC0_0000);
}

#[test]
fn multiply_add_rounds_once() {
    let nj = vscr(true);
    // 1.1 × 1.1 + 1.1: one rounding gives 0x4013D70B; rounding the product first gives 70A.
    let x = splat(0x3F8C_CCCD);
    assert_eq!(vmaddfp(nj, x, x, x), splat(0x4013_D70B));
    // (1 + 2^-12)^2 + 2^-80 is just above the midpoint 1 + 2^-11 + 2^-24, so it rounds up; a
    // fused double rounded to single would land on the midpoint and tie down to 0x3F801000.
    let a = splat(0x3F80_0800);
    assert_eq!(vmaddfp(nj, a, a, splat(0x1780_0000)), splat(0x3F80_1001));
    // -(1.1 × 1.1 - 1.1), rounded once, then negated.
    assert_eq!(vnmsubfp(nj, x, x, x), splat(0xBDE1_47B2));
    // 1 × 1 - 1 is +0, negated to -0.
    assert_eq!(
        vnmsubfp(nj, splat(ONE), splat(ONE), splat(ONE)),
        splat(NEG_ZERO)
    );
}

#[test]
fn multiply_add_nans_follow_the_register_order() {
    let nj = vscr(true);
    // vmaddfp vD, vA, vC, vB: the addend vB ranks before the multiplier vC.
    assert_eq!(
        vmaddfp(nj, splat(ONE), splat(QNAN_C), splat(QNAN_B)),
        splat(QNAN_B)
    );
    assert_eq!(
        vmaddfp(nj, splat(QNAN_A), splat(QNAN_C), splat(QNAN_B)),
        splat(QNAN_A)
    );
    assert_eq!(
        vmaddfp(nj, splat(ONE), splat(QNAN_C), splat(ONE)),
        splat(QNAN_C)
    );
    // vnmsubfp does not negate a NaN.
    assert_eq!(
        vnmsubfp(nj, splat(QNAN_A), splat(ONE), splat(ONE)),
        splat(QNAN_A)
    );
    // Infinity times zero, and an infinite product against an infinity of the other sign.
    assert_eq!(
        vmaddfp(nj, splat(INF), splat(0), splat(ONE)),
        splat(VECTOR_DEFAULT_NAN)
    );
    assert_eq!(
        vmaddfp(nj, splat(INF), splat(ONE), splat(NEG_INF)),
        splat(VECTOR_DEFAULT_NAN)
    );
    assert_eq!(
        vnmsubfp(nj, splat(INF), splat(ONE), splat(INF)),
        splat(VECTOR_DEFAULT_NAN)
    );
    assert_eq!(
        vnmsubfp(nj, splat(INF), splat(ONE), splat(ONE)),
        splat(NEG_INF)
    );
}

#[test]
fn maximum_and_minimum_order_zeros_and_pass_nans() {
    let nj = vscr(true);
    let a = v(NEG_ZERO, 0, 0xBF80_0000, QNAN_A);
    let b = v(0, NEG_ZERO, TWO, ONE);
    assert_eq!(vmaxfp(nj, a, b), v(0, 0, TWO, QNAN_A));
    assert_eq!(vminfp(nj, a, b), v(NEG_ZERO, NEG_ZERO, 0xBF80_0000, QNAN_A));
    assert_eq!(vmaxfp(nj, splat(ONE), splat(SNAN_B)), splat(0x7FC0_00BB));
    assert_eq!(vmaxfp(nj, splat(NEG_INF), splat(INF)), splat(INF));
    // A denormal is a zero in non-Java mode, so the result is the flushed zero.
    assert_eq!(vmaxfp(vscr(true), splat(DENORMAL), splat(0)), splat(0));
    assert_eq!(
        vmaxfp(vscr(false), splat(DENORMAL), splat(0)),
        splat(DENORMAL)
    );
    assert_eq!(
        vminfp(vscr(true), splat(DENORMAL | NEG_ZERO), splat(0)),
        splat(NEG_ZERO)
    );
}

#[test]
fn rounding_to_an_integer_follows_each_mode() {
    let nj = vscr(true);
    // 1.5, -1.5, 2.5, -0.3.
    let x = v(0x3FC0_0000, 0xBFC0_0000, 0x4020_0000, 0xBE99_999A);
    assert_eq!(vrfin(nj, x), v(TWO, 0xC000_0000, TWO, NEG_ZERO));
    assert_eq!(vrfiz(nj, x), v(ONE, 0xBF80_0000, TWO, NEG_ZERO));
    assert_eq!(vrfip(nj, x), v(TWO, 0xBF80_0000, THREE, NEG_ZERO));
    assert_eq!(vrfim(nj, x), v(ONE, 0xC000_0000, TWO, 0xBF80_0000));
    // 8388607.5 ties to the even 8388608; toward zero it is 8388607.
    assert_eq!(vrfin(nj, splat(0x4AFF_FFFF)), splat(0x4B00_0000));
    assert_eq!(vrfiz(nj, splat(0x4AFF_FFFF)), splat(0x4AFF_FFFE));
    let specials = v(INF, NEG_INF, SNAN_B, DENORMAL | NEG_ZERO);
    assert_eq!(vrfip(nj, specials), v(INF, NEG_INF, 0x7FC0_00BB, NEG_ZERO));
    assert_eq!(
        vrfip(vscr(false), splat(DENORMAL)),
        splat(ONE),
        "Java mode rounds the denormal itself up"
    );
}

#[test]
fn reciprocal_estimates_are_correctly_rounded() {
    let nj = vscr(true);
    // 1/2, 1/-0, 1/+inf, 1/3.
    assert_eq!(
        vrefp(nj, v(TWO, NEG_ZERO, INF, THREE)),
        v(HALF, NEG_INF, 0, 0x3EAA_AAAB)
    );
    assert_eq!(vrefp(nj, splat(DENORMAL)), splat(INF), "a flushed denormal");
    // 1/2^127 = 2^-127 is a denormal: flushed in non-Java mode, kept otherwise.
    assert_eq!(vrefp(vscr(true), splat(0x7F00_0000)), splat(0));
    assert_eq!(vrefp(vscr(false), splat(0x7F00_0000)), splat(0x0040_0000));
    // 1/sqrt(4), 1/sqrt(-0), 1/sqrt(+inf), 1/sqrt(-1).
    assert_eq!(
        vrsqrtefp(nj, v(0x4080_0000, NEG_ZERO, INF, 0xBF80_0000)),
        v(HALF, NEG_INF, 0, VECTOR_DEFAULT_NAN)
    );
    assert_eq!(
        vrsqrtefp(nj, v(0, TWO, NEG_INF, QNAN_A)),
        v(INF, 0x3F35_04F3, VECTOR_DEFAULT_NAN, QNAN_A)
    );
}

#[test]
fn exponent_estimates_are_exact_for_integers_and_correctly_rounded_otherwise() {
    let nj = vscr(true);
    // The suite's case: 2^2, 2^3, 2^4, 2^5.
    assert_eq!(
        vexptefp(nj, v(TWO, THREE, 0x4080_0000, 0x40A0_0000)),
        v(0x4080_0000, 0x4100_0000, 0x4180_0000, 0x4200_0000)
    );
    assert_eq!(
        vexptefp(nj, v(NEG_INF, INF, NEG_ZERO, 0xC2FC_0000)),
        v(0, INF, ONE, MIN_NORMAL),
        "-inf, +inf, -0 and -126"
    );
    // 2^127 is the largest power; 2^128 overflows.
    assert_eq!(
        vexptefp(nj, v(0x42FE_0000, 0x4300_0000, HALF, SNAN_B)),
        v(0x7F00_0000, INF, 0x3FB5_04F3, 0x7FC0_00BB)
    );
    // 2^-149 is the smallest denormal: flushed in non-Java mode. 2^-150 ties to 0 either way.
    let tiny = v(0xC315_0000, 0xC316_0000, 0, 0);
    assert_eq!(vexptefp(vscr(true), tiny), v(0, 0, ONE, ONE));
    assert_eq!(vexptefp(vscr(false), tiny), v(DENORMAL, 0, ONE, ONE));
    // Values from 60-digit decimal arithmetic, rounded to the nearest single: 2^1.23,
    // 2^-10.2044..., 2^123.456..., 2^-0.2, 2^10 and 2^0.1.
    for (x, expected) in [
        (0x3F9D_70A4, 0x4016_1F75),
        (0xC123_4567, 0x3A5E_2CEF),
        (0x42F6_E979, 0x7D2F_94FF),
        (0xBE4C_CCCD, 0x3F5E_DC67),
        (0x4120_0000, 0x4480_0000),
        (0x3DCC_CCCD, 0x3F89_2FDF),
    ] {
        assert_eq!(vexptefp(nj, splat(x)), splat(expected), "2^{x:#010x}");
    }
}

#[test]
fn logarithm_estimates_are_exact_for_powers_of_two_and_correctly_rounded_otherwise() {
    let nj = vscr(true);
    assert_eq!(
        vlogefp(nj, v(0x4100_0000, HALF, ONE, 0x4480_0000)),
        v(THREE, 0xBF80_0000, 0, 0x4120_0000),
        "log2 of 8, 0.5, 1 and 1024"
    );
    assert_eq!(
        vlogefp(nj, v(NEG_ZERO, 0, 0xBF80_0000, INF)),
        v(NEG_INF, NEG_INF, VECTOR_DEFAULT_NAN, INF)
    );
    assert_eq!(vlogefp(nj, splat(NEG_INF)), splat(VECTOR_DEFAULT_NAN));
    // A denormal is zero in non-Java mode; in Java mode log2(2^-149) is -149.
    assert_eq!(vlogefp(vscr(true), splat(DENORMAL)), splat(NEG_INF));
    assert_eq!(vlogefp(vscr(false), splat(DENORMAL)), splat(0xC315_0000));
    for (x, expected) in [
        (THREE, 0x3FCA_E00D),
        (0x3F9D_70A4, 0x3E98_E9BF),
        (0x4B3B_DF83, 0x41BC_6DCE),
        (0x3DCC_CCCD, 0xC054_9A78),
        (0x7F7F_FFFF, 0x4300_0000),
        (0x3F7F_FFFF, 0xB3B8_AA3C),
        (0x3F80_0001, 0x3438_AA3A),
    ] {
        assert_eq!(vlogefp(nj, splat(x)), splat(expected), "log2 {x:#010x}");
    }
}

#[test]
fn conversions_from_integers_round_to_nearest_even_and_scale_exactly() {
    // 1, -1, 2^31 - 1 (rounds to 2^31), -2^31.
    let x = v(1, u32::MAX, 0x7FFF_FFFF, 0x8000_0000);
    assert_eq!(vcfsx(x, 0), v(ONE, 0xBF80_0000, 0x4F00_0000, 0xCF00_0000));
    assert_eq!(vcfsx(x, 31), v(0x3000_0000, 0xB000_0000, ONE, 0xBF80_0000));
    assert_eq!(vcfux(x, 0), v(ONE, 0x4F80_0000, 0x4F00_0000, 0x4F00_0000));
    assert_eq!(vcfux(x, 1).0[1], 0x4F00_0000, "2^32 / 2");
    // 2^24 + 1 ties to 2^24; 2^24 + 3 ties to 2^24 + 4.
    assert_eq!(
        vcfsx(v(0x0100_0001, 0x0100_0003, 0, 0), 0),
        v(0x4B80_0000, 0x4B80_0002, 0, 0)
    );
    // The suite's case: the bits of 1.0 as an integer, 1065353216, is 0x4E7E0000.
    assert_eq!(vcfsx(splat(ONE), 0), splat(0x4E7E_0000));
}

#[test]
fn conversions_to_signed_words_truncate_and_saturate() {
    let mut s = vscr(true);
    // 2^31 saturates; -2^31 fits; a NaN gives 0; 2.9 truncates to 2.
    let r = vctsxs(&mut s, v(0x4F00_0000, 0xCF00_0000, QNAN_A, 0x4039_999A), 0);
    assert_eq!(r, v(0x7FFF_FFFF, 0x8000_0000, 0, 2));
    assert!(s.sat());
    let mut s = vscr(true);
    // -2.9 truncates to -2; a negative denormal gives 0; 1.5 × 2^1 = 3; a NaN leaves SAT alone.
    let r = vctsxs(
        &mut s,
        v(0xC039_999A, DENORMAL | NEG_ZERO, 0x3FC0_0000, SNAN_B),
        1,
    );
    assert_eq!(r, v(0xFFFF_FFFB, 0, 3, 0));
    assert!(!s.sat());
    let r = vctsxs(&mut s, v(INF, NEG_INF, 0, 0), 0);
    assert_eq!(r, v(0x7FFF_FFFF, 0x8000_0000, 0, 0));
    assert!(s.sat());
}

#[test]
fn conversions_to_unsigned_words_truncate_and_saturate() {
    let mut s = vscr(true);
    // -0.5 truncates to zero without saturating; 2^32 - 256 fits.
    let r = vctuxs(&mut s, v(0xBF00_0000, 0x4F7F_FFFF, QNAN_A, ONE), 0);
    assert_eq!(r, v(0, 0xFFFF_FF00, 0, 1));
    assert!(!s.sat());
    let mut s = vscr(true);
    assert_eq!(vctuxs(&mut s, splat(0xBF80_0000), 0), splat(0), "-1");
    assert!(s.sat());
    let mut s = vscr(true);
    assert_eq!(
        vctuxs(&mut s, splat(0x4F80_0000), 0),
        splat(u32::MAX),
        "2^32"
    );
    assert!(s.sat());
    let mut s = vscr(true);
    assert_eq!(
        vctuxs(&mut s, v(INF, NEG_INF, 0x4F00_0000, 0x3F00_0000), 31),
        v(u32::MAX, 0, u32::MAX, 0x4000_0000),
        "0.5 × 2^31 is 2^30"
    );
    assert!(s.sat());
}

#[test]
fn floating_point_compares_are_false_for_nans() {
    let nj = vscr(true);
    let a = v(0, QNAN_A, ONE, TWO);
    let b = v(NEG_ZERO, QNAN_A, TWO, ONE);
    assert_eq!(vcmpeqfp(nj, a, b), v(u32::MAX, 0, 0, 0));
    assert_eq!(vcmpgefp(nj, a, b), v(u32::MAX, 0, 0, u32::MAX));
    assert_eq!(vcmpgtfp(nj, a, b), v(0, 0, 0, u32::MAX));
    // A denormal equals zero only in non-Java mode.
    assert_eq!(
        vcmpeqfp(vscr(true), splat(DENORMAL), splat(0)),
        splat(u32::MAX)
    );
    assert_eq!(vcmpeqfp(vscr(false), splat(DENORMAL), splat(0)), splat(0));
}

#[test]
fn bounds_compares_set_two_bits_per_element() {
    let nj = vscr(true);
    // 7 against 5, -7 against 5, 5 against 5, and a NaN.
    let a = v(0x40E0_0000, 0xC0E0_0000, 0x40A0_0000, QNAN_A);
    let b = v(0x40A0_0000, 0x40A0_0000, 0x40A0_0000, ONE);
    let r = vcmpbfp(nj, a, b);
    assert_eq!(r, v(0x8000_0000, 0x4000_0000, 0, 0xC000_0000));
    assert_eq!(vcmpbfp_cr6(r), 0);
    assert_eq!(vcmpbfp_cr6(V128::ZERO), 0b0010);
    // A negative bound: 1 is above -1 but not below 1.
    assert_eq!(
        vcmpbfp(nj, splat(ONE), splat(0xBF80_0000)),
        splat(0x8000_0000)
    );
}

#[test]
fn compare_records_report_all_or_none() {
    assert_eq!(vcmp_cr6(splat(u32::MAX)), 0b1000);
    assert_eq!(vcmp_cr6(V128::ZERO), 0b0010);
    assert_eq!(vcmp_cr6(v(u32::MAX, u32::MAX, u32::MAX, 0)), 0);
    assert_eq!(vcmp_cr6(v(0, 0, 0, 0xFF00_0000)), 0);
}

#[test]
fn dot_products_add_the_exact_products_and_splat() {
    let nj = vscr(true);
    // The suite's cases: 10.166 and 20.635, rounded once.
    let a = v(ONE, 0x3FC0_0000, 0x3F8C_CCCD, 0x3FF3_3333);
    let b = v(TWO, 0x4070_0000, 0x4013_D70A, 0x40B0_51EB);
    assert_eq!(vmsum4fp128(nj, a, b), splat(0x41A5_147B));
    let a3 = v(ONE, 0x3FC0_0000, 0x3F8C_CCCD, QNAN_A);
    assert_eq!(
        vmsum3fp128(nj, a3, b),
        splat(0x4122_A7F0),
        "word 3 does not count"
    );
    // The first NaN in word order, vA before vB in a word.
    assert_eq!(
        vmsum3fp128(nj, v(ONE, QNAN_A, 0, 0), v(QNAN_B, ONE, 0, 0)),
        splat(QNAN_B)
    );
    assert_eq!(
        vmsum4fp128(nj, v(INF, 0, 0, 0), v(0, 0, 0, 0)),
        splat(VECTOR_DEFAULT_NAN)
    );
    // Denormal products flush in non-Java mode.
    let tiny = splat(0x1F80_0000); // 2^-64
    assert_eq!(vmsum3fp128(vscr(true), tiny, tiny), splat(0));
    assert_eq!(vmsum3fp128(vscr(false), tiny, tiny), splat(0x0060_0000));
}

#[test]
fn the_vscr_starts_in_non_java_mode() {
    assert!(Vscr::default().nj());
}
