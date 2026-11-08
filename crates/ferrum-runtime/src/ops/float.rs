// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The floating-point instructions of Book I, chapter 4, for generated code to call.
//!
//! A Rust operation may return any NaN, so every helper whose result can be a NaN picks it by the
//! rule of 4.3.2: frA if it is a NaN, else frB, else frC, with the quiet bit set; otherwise the
//! NaN the operation generated, [`DEFAULT_NAN`]. The fast path is the host operation and one test
//! of its result; a NaN, or a zero divisor, takes a cold path that picks the NaN and records the
//! exception in the [`Fpscr`].
//!
//! The operands follow the instruction: `fmul(fpscr, a, c)` is `fmul frT, frA, frC`, and
//! `fmadd(fpscr, a, c, b)` is `fmadd frT, frA, frC, frB`, which computes `a × c + b`.

use crate::Fpscr;

#[cfg(test)]
mod tests;

const SIGN: u64 = 1 << 63;
const EXPONENT: u64 = 0x7FF0_0000_0000_0000;
const FRACTION: u64 = 0x000F_FFFF_FFFF_FFFF;
/// The high bit of the fraction, set in a quiet NaN.
const QUIET: u64 = 1 << 51;
/// The fraction bits that single format lacks.
const SINGLE_LOW: u64 = (1 << 29) - 1;

/// The bits of the NaN an invalid operation generates: positive, quiet, no payload.
pub const DEFAULT_NAN: u64 = 0x7FF8_0000_0000_0000;

/// Returns whether `x` is a signaling NaN: a NaN whose quiet bit is clear.
pub(crate) fn is_snan(x: f64) -> bool {
    x.is_nan() && x.to_bits() & QUIET == 0
}

fn quiet(x: f64) -> f64 {
    f64::from_bits(x.to_bits() | QUIET)
}

/// VXSNAN if any of `operands` is a signaling NaN.
fn snan_bit(operands: &[f64]) -> u32 {
    if operands.iter().any(|&x| is_snan(x)) {
        Fpscr::VXSNAN
    } else {
        0
    }
}

/// The result of an operation whose host result was a NaN: the first NaN of `operands`, given in
/// the order frA, frB, frC, quieted; or, if none is a NaN, [`DEFAULT_NAN`] with the exception
/// bit `generated` of the invalid operation.
fn nan_result(fpscr: &mut Fpscr, operands: &[f64], generated: u32) -> f64 {
    match operands.iter().find(|x| x.is_nan()) {
        Some(&nan) => {
            fpscr.raise(snan_bit(operands));
            quiet(nan)
        }
        None => {
            fpscr.raise(generated);
            f64::from_bits(DEFAULT_NAN)
        }
    }
}

/// `fneg`: `x` with its sign bit inverted, a NaN included.
#[inline]
pub fn fneg(x: f64) -> f64 {
    f64::from_bits(x.to_bits() ^ SIGN)
}

/// `fabs`: `x` with its sign bit cleared, a NaN included.
#[inline]
pub fn fabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & !SIGN)
}

/// `fnabs`: `x` with its sign bit set, a NaN included.
#[inline]
pub fn fnabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() | SIGN)
}

/// `fsel`: `c` if `a` is greater than or equal to zero, -0 included; `b` if it is less or a NaN.
#[inline]
pub fn fsel(a: f64, c: f64, b: f64) -> f64 {
    if a >= 0.0 { c } else { b }
}

/// `fadd`: `a + b`.
#[inline]
pub fn fadd(fpscr: &mut Fpscr, a: f64, b: f64) -> f64 {
    let r = a + b;
    if r.is_nan() { add_nan(fpscr, a, b) } else { r }
}

/// `fsub`: `a - b`.
#[inline]
pub fn fsub(fpscr: &mut Fpscr, a: f64, b: f64) -> f64 {
    let r = a - b;
    if r.is_nan() { add_nan(fpscr, a, b) } else { r }
}

/// A NaN from an addition or a subtraction: infinity minus infinity when no operand is a NaN.
#[cold]
#[inline(never)]
fn add_nan(fpscr: &mut Fpscr, a: f64, b: f64) -> f64 {
    nan_result(fpscr, &[a, b], Fpscr::VXISI)
}

/// `fmul`: `a × c`.
#[inline]
pub fn fmul(fpscr: &mut Fpscr, a: f64, c: f64) -> f64 {
    let r = a * c;
    if r.is_nan() { mul_nan(fpscr, a, c) } else { r }
}

/// A NaN from a multiplication: infinity times zero when no operand is a NaN.
#[cold]
#[inline(never)]
fn mul_nan(fpscr: &mut Fpscr, a: f64, c: f64) -> f64 {
    nan_result(fpscr, &[a, c], Fpscr::VXIMZ)
}

/// `fdiv`: `a / b`. A finite non-zero `a` over zero gives an infinity and sets ZX.
#[inline]
pub fn fdiv(fpscr: &mut Fpscr, a: f64, b: f64) -> f64 {
    let r = a / b;
    if r.is_nan() || b == 0.0 {
        div_special(fpscr, a, b, r)
    } else {
        r
    }
}

#[cold]
#[inline(never)]
fn div_special(fpscr: &mut Fpscr, a: f64, b: f64, r: f64) -> f64 {
    if !r.is_nan() {
        // A number over zero: an infinity with the sign of the quotient, which the host gives.
        // Only a finite dividend is a zero divide; infinity over zero is exact.
        if a.is_finite() {
            fpscr.raise(Fpscr::ZX);
        }
        return r;
    }
    let generated = if a.is_infinite() {
        Fpscr::VXIDI
    } else {
        Fpscr::VXZDZ
    };
    nan_result(fpscr, &[a, b], generated)
}

/// `fsqrt`: the square root of `b`. The root of -0 is -0; that of a negative number is a NaN.
#[inline]
pub fn fsqrt(fpscr: &mut Fpscr, b: f64) -> f64 {
    let r = b.sqrt();
    if r.is_nan() { sqrt_nan(fpscr, b) } else { r }
}

#[cold]
#[inline(never)]
fn sqrt_nan(fpscr: &mut Fpscr, b: f64) -> f64 {
    nan_result(fpscr, &[b], Fpscr::VXSQRT)
}

/// `fmadd`: `a × c + b` with one rounding.
#[inline]
pub fn fmadd(fpscr: &mut Fpscr, a: f64, c: f64, b: f64) -> f64 {
    let r = a.mul_add(c, b);
    if r.is_nan() {
        madd_nan(fpscr, a, c, b, false)
    } else {
        r
    }
}

/// `fmsub`: `a × c - b` with one rounding.
#[inline]
pub fn fmsub(fpscr: &mut Fpscr, a: f64, c: f64, b: f64) -> f64 {
    let r = a.mul_add(c, -b);
    if r.is_nan() {
        madd_nan(fpscr, a, c, b, true)
    } else {
        r
    }
}

/// `fnmadd`: `-(a × c + b)`, negated after the rounding. A NaN is not negated.
#[inline]
pub fn fnmadd(fpscr: &mut Fpscr, a: f64, c: f64, b: f64) -> f64 {
    let r = a.mul_add(c, b);
    if r.is_nan() {
        madd_nan(fpscr, a, c, b, false)
    } else {
        fneg(r)
    }
}

/// `fnmsub`: `-(a × c - b)`, negated after the rounding. A NaN is not negated.
#[inline]
pub fn fnmsub(fpscr: &mut Fpscr, a: f64, c: f64, b: f64) -> f64 {
    let r = a.mul_add(c, -b);
    if r.is_nan() {
        madd_nan(fpscr, a, c, b, true)
    } else {
        fneg(r)
    }
}

/// A NaN from a multiply-add. The exception bits are those of a multiplication followed by an
/// addition (4.6.5.2): infinity times zero whatever the addend, and infinity minus infinity when
/// the product is an infinity and the addend, after the negation of a subtract, the opposite one.
#[cold]
#[inline(never)]
fn madd_nan(fpscr: &mut Fpscr, a: f64, c: f64, b: f64, subtract: bool) -> f64 {
    let mut bits = snan_bit(&[a, b, c]);
    let imz = (a == 0.0 && c.is_infinite()) || (a.is_infinite() && c == 0.0);
    if imz {
        bits |= Fpscr::VXIMZ;
    }
    let infinite_product =
        (a.is_infinite() || c.is_infinite()) && !imz && !a.is_nan() && !c.is_nan();
    if infinite_product && b.is_infinite() {
        let product_negative = a.is_sign_negative() != c.is_sign_negative();
        let addend_negative = b.is_sign_negative() != subtract;
        if product_negative != addend_negative {
            bits |= Fpscr::VXISI;
        }
    }
    fpscr.raise(bits);
    match [a, b, c].into_iter().find(|x| x.is_nan()) {
        Some(nan) => quiet(nan),
        None => f64::from_bits(DEFAULT_NAN),
    }
}

/// Rounds `x` to the nearest single, in double format, as `frsp` does in round-to-nearest: an
/// overflow gives an infinity of the same sign, and a NaN keeps bits 0:34 with the quiet bit set.
fn to_single(x: f64) -> f64 {
    if x.is_nan() {
        f64::from_bits((x.to_bits() & !SINGLE_LOW) | QUIET)
    } else {
        // A float-to-float cast: Rust rounds to the nearest single, ties to even, and an overflow
        // to an infinity. Widening the single back is exact.
        f64::from(x as f32)
    }
}

/// `frsp`: `b` rounded to single.
#[inline]
pub fn frsp(fpscr: &mut Fpscr, b: f64) -> f64 {
    if is_snan(b) {
        fpscr.raise(Fpscr::VXSNAN);
    }
    to_single(b)
}

/// `fadds`: `a + b` rounded to single. For single operands, rounding the double sum is rounding
/// the exact sum once, because 53 >= 2 × 24 + 2 (S. Figueroa, "When is double rounding
/// innocuous?", SIGNUM Newsletter 30(3), 1995).
#[inline]
pub fn fadds(fpscr: &mut Fpscr, a: f64, b: f64) -> f64 {
    to_single(fadd(fpscr, a, b))
}

/// `fsubs`: `a - b` rounded to single.
#[inline]
pub fn fsubs(fpscr: &mut Fpscr, a: f64, b: f64) -> f64 {
    to_single(fsub(fpscr, a, b))
}

/// `fmuls`: `a × c` rounded to single. The double product of two singles is exact.
#[inline]
pub fn fmuls(fpscr: &mut Fpscr, a: f64, c: f64) -> f64 {
    to_single(fmul(fpscr, a, c))
}

/// `fdivs`: `a / b` rounded to single.
#[inline]
pub fn fdivs(fpscr: &mut Fpscr, a: f64, b: f64) -> f64 {
    to_single(fdiv(fpscr, a, b))
}

/// `fsqrts`: the square root of `b` rounded to single.
#[inline]
pub fn fsqrts(fpscr: &mut Fpscr, b: f64) -> f64 {
    to_single(fsqrt(fpscr, b))
}

/// `fmadds`: `a × c + b` rounded once to single.
#[inline]
pub fn fmadds(fpscr: &mut Fpscr, a: f64, c: f64, b: f64) -> f64 {
    let r = a.mul_add(c, b);
    if r.is_nan() {
        return to_single(madd_nan(fpscr, a, c, b, false));
    }
    to_single(round_to_odd(a, c, b, r))
}

/// `fmsubs`: `a × c - b` rounded once to single.
#[inline]
pub fn fmsubs(fpscr: &mut Fpscr, a: f64, c: f64, b: f64) -> f64 {
    let r = a.mul_add(c, -b);
    if r.is_nan() {
        return to_single(madd_nan(fpscr, a, c, b, true));
    }
    to_single(round_to_odd(a, c, -b, r))
}

/// `fnmadds`: `-(a × c + b)` rounded once to single, then negated. A NaN is not negated.
#[inline]
pub fn fnmadds(fpscr: &mut Fpscr, a: f64, c: f64, b: f64) -> f64 {
    let r = a.mul_add(c, b);
    if r.is_nan() {
        return to_single(madd_nan(fpscr, a, c, b, false));
    }
    fneg(to_single(round_to_odd(a, c, b, r)))
}

/// `fnmsubs`: `-(a × c - b)` rounded once to single, then negated. A NaN is not negated.
#[inline]
pub fn fnmsubs(fpscr: &mut Fpscr, a: f64, c: f64, b: f64) -> f64 {
    let r = a.mul_add(c, -b);
    if r.is_nan() {
        return to_single(madd_nan(fpscr, a, c, b, true));
    }
    fneg(to_single(round_to_odd(a, c, -b, r)))
}

/// `a × c + b` rounded to odd in double, given `fused`, the same sum rounded to nearest. Rounding
/// the result to single then rounds the exact sum once, as the fused single forms do: a double
/// rounded to nearest can land on the midpoint between two singles and send the second rounding
/// the wrong way, and one rounded to odd cannot (Boldo and Melquiond, 2008).
///
/// For single operands the product is exact in double, so the sum and its error (TwoSum) are the
/// exact result. With other operands, which the ISA leaves undefined, it returns `fused`.
fn round_to_odd(a: f64, c: f64, b: f64, fused: f64) -> f64 {
    let (sum, error) = two_sum(a * c, b);
    if !sum.is_finite() || sum != fused {
        return fused;
    }
    to_odd(sum, error)
}

/// Knuth's TwoSum: `x + y` rounded to nearest, and the exact error of that rounding, for finite
/// `x` and `y` whose sum does not overflow.
pub(crate) fn two_sum(x: f64, y: f64) -> (f64, f64) {
    let sum = x + y;
    let y_part = sum - x;
    let error = (x - (sum - y_part)) + (y - y_part);
    (sum, error)
}

/// The exact value `sum + error` rounded to odd, given `sum`, that value rounded to nearest, and
/// `error`, the rest.
pub(crate) fn to_odd(sum: f64, error: f64) -> f64 {
    if error == 0.0 || sum.to_bits() & 1 == 1 {
        return sum;
    }
    // An inexact even result: the exact sum lies between it and its neighbor toward the error,
    // which is odd. Moving the bits by one moves the magnitude by one unit in the last place.
    let away_from_zero = (error > 0.0) == (sum > 0.0);
    let bits = if away_from_zero {
        sum.to_bits().wrapping_add(1)
    } else {
        sum.to_bits().wrapping_sub(1)
    };
    f64::from_bits(bits)
}

/// `fres`: the reciprocal of `b` rounded to single. The ISA asks for an estimate within one part
/// in 256; this is the exact reciprocal, rounded. Zero gives an infinity of its sign and sets ZX.
#[inline]
pub fn fres(fpscr: &mut Fpscr, b: f64) -> f64 {
    let r = 1.0 / b;
    if r.is_nan() || b == 0.0 {
        return to_single(estimate_special(fpscr, b, r));
    }
    to_single(r)
}

/// `frsqrte`: the reciprocal square root of `b` in double. The ISA asks for an estimate within one
/// part in 32; this is `1 / sqrt(b)`. A negative number gives a NaN and sets VXSQRT; ±0 give an
/// infinity of their sign and set ZX; +infinity gives +0.
#[inline]
pub fn frsqrte(fpscr: &mut Fpscr, b: f64) -> f64 {
    let r = 1.0 / b.sqrt();
    if r.is_nan() || b == 0.0 {
        return estimate_special(fpscr, b, r);
    }
    r
}

/// The special values of `fres` and `frsqrte` (5.2.1): `r` is the host result.
#[cold]
#[inline(never)]
fn estimate_special(fpscr: &mut Fpscr, b: f64, r: f64) -> f64 {
    if b == 0.0 {
        fpscr.raise(Fpscr::ZX);
        return r;
    }
    nan_result(fpscr, &[b], Fpscr::VXSQRT)
}

/// 2^31 as a double.
const TWO_31: f64 = 2_147_483_648.0;
/// 2^63 as a double.
const TWO_63: f64 = 9_223_372_036_854_775_808.0;

/// `fctiw`: `b` rounded to the nearest integer, ties to even, as a word (see [`fctiwz`]).
#[inline]
pub fn fctiw(fpscr: &mut Fpscr, b: f64) -> f64 {
    to_word(fpscr, b, b.round_ties_even())
}

/// `fctiwz`: `b` rounded toward zero to a word, in the low word of the result. Out of range, the
/// largest or smallest word; a NaN gives the smallest; both set VXCVI. The ISA leaves the high
/// word undefined; here it is the sign extension of the low one, as the suite expects.
#[inline]
pub fn fctiwz(fpscr: &mut Fpscr, b: f64) -> f64 {
    to_word(fpscr, b, b.trunc())
}

/// `fctid`: `b` rounded to the nearest integer, ties to even, as a doubleword (see [`fctidz`]).
#[inline]
pub fn fctid(fpscr: &mut Fpscr, b: f64) -> f64 {
    to_doubleword(fpscr, b, b.round_ties_even())
}

/// `fctidz`: `b` rounded toward zero to a doubleword. Out of range, the largest or smallest
/// doubleword; a NaN gives the smallest; both set VXCVI.
#[inline]
pub fn fctidz(fpscr: &mut Fpscr, b: f64) -> f64 {
    to_doubleword(fpscr, b, b.trunc())
}

/// The word of a conversion of `b`, already rounded to `rounded`, saturated as Appendix A.2 does.
fn to_word(fpscr: &mut Fpscr, b: f64, rounded: f64) -> f64 {
    let word = if b.is_nan() {
        fpscr.raise(snan_bit(&[b]) | Fpscr::VXCVI);
        i32::MIN
    } else if rounded >= TWO_31 {
        fpscr.raise(Fpscr::VXCVI);
        i32::MAX
    } else if rounded < -TWO_31 {
        fpscr.raise(Fpscr::VXCVI);
        i32::MIN
    } else {
        // In range, so the cast to the low word loses nothing.
        integral_to_i64(rounded) as i32
    };
    // The bits of the sign-extended word are the result.
    f64::from_bits(i64::from(word) as u64)
}

/// The doubleword of a conversion of `b`, already rounded to `rounded`, saturated as Appendix A.2
/// does.
fn to_doubleword(fpscr: &mut Fpscr, b: f64, rounded: f64) -> f64 {
    let value = if b.is_nan() {
        fpscr.raise(snan_bit(&[b]) | Fpscr::VXCVI);
        i64::MIN
    } else if rounded >= TWO_63 {
        fpscr.raise(Fpscr::VXCVI);
        i64::MAX
    } else if rounded < -TWO_63 {
        fpscr.raise(Fpscr::VXCVI);
        i64::MIN
    } else {
        integral_to_i64(rounded)
    };
    // The bits of the two's complement are the result.
    f64::from_bits(value as u64)
}

/// The integer that an integral double in `[-2^63, 2^63)` holds, read from its bits, so that
/// nothing depends on how an `as` cast saturates.
pub(crate) fn integral_to_i64(x: f64) -> i64 {
    let bits = x.to_bits();
    let biased = (bits & EXPONENT) >> 52;
    if biased == 0 {
        // Zero: an integral value is never a denormal.
        return 0;
    }
    let significand = (bits & FRACTION) | (1 << 52);
    // The last bit of the significand weighs 2^(biased - 1075).
    let magnitude = if biased >= 1075 {
        significand << (biased - 1075)
    } else {
        significand >> (1075 - biased)
    };
    // At most 2^63, whose bits read as i64::MIN, which negating leaves alone.
    let magnitude = magnitude as i64;
    if bits & SIGN != 0 {
        magnitude.wrapping_neg()
    } else {
        magnitude
    }
}

/// `fcfid`: the doubleword in the bits of `b`, as a signed integer, rounded to the nearest double.
#[inline]
pub fn fcfid(b: f64) -> f64 {
    // The bits are a two's complement integer.
    let value = b.to_bits() as i64;
    // The arithmetic shift leaves a value that fits a word; the low word is a truncation.
    let high = (value >> 32) as i32;
    let low = value as u32;
    // Both halves convert exactly, and so does the product by 2^32; the sum rounds once.
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

/// `lfs`: the double that holds the single `word`, converted bit for bit as 4.6.2 describes. A
/// signaling NaN stays signaling.
#[inline]
pub fn single_to_double(word: u32) -> f64 {
    let single = f32::from_bits(word);
    if single.is_finite() {
        // Widening a finite single is exact, denormals included.
        f64::from(single)
    } else {
        // An infinity or a NaN: the sign, an exponent of all ones, and the fraction moved up.
        let word = u64::from(word);
        f64::from_bits(((word & 0x8000_0000) << 32) | EXPONENT | ((word & 0x007F_FFFF) << 29))
    }
}

/// `stfs`: the single word for `x`, selected from its bits as 4.6.3 describes, without rounding.
///
/// Above the single denormal range, and for zero, infinity and NaN, the word is bits 0:1 and 5:34.
/// Within it, the significand is shifted right and truncated. Below it, which the ISA leaves
/// undefined, the shift leaves a zero of the same sign.
#[inline]
pub fn double_to_single(x: f64) -> u32 {
    let bits = x.to_bits();
    let biased = (bits & EXPONENT) >> 52;
    let word = if biased > 896 || bits & !SIGN == 0 {
        ((bits >> 32) & 0xC000_0000) | ((bits >> 29) & 0x3FFF_FFFF)
    } else {
        // Shift the significand, unit bit included, until the exponent is -126, and keep the 23
        // bits after the unit position. The exponent is biased - 1023, so the shift is
        // 897 - biased, plus 29 to drop the bits single lacks.
        let significand = (bits & FRACTION) | (1 << 52);
        let shift = 897 - biased + 29;
        let fraction = if shift < 64 { significand >> shift } else { 0 };
        ((bits >> 32) & 0x8000_0000) | fraction
    };
    // Both branches build a value of 32 bits.
    word as u32
}
