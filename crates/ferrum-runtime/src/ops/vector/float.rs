// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The vector floating-point instructions of Book I, chapter 6 (Power ISA v3.1C), and their
//! VMX128 forms.
//!
//! A lane is a single held as its 32 bits. Every helper takes the [`Vscr`]: with NJ set, a
//! denormal source is used as a zero of its sign, and a result whose exact value is nonzero and
//! below 2^-126 in magnitude becomes a zero of its sign (6.6.2.6, before rounding). Results are
//! computed in double from the exact operands and rounded once to single. A NaN result is the
//! first NaN operand in the order vA, vB, vC, quieted, or [`VECTOR_DEFAULT_NAN`] for an invalid
//! operation (6.6.2.1).
//!
//! The operands follow the instruction: `vmaddfp(vscr, a, c, b)` is `vmaddfp vD, vA, vC, vB`,
//! which computes `a × c + b`, and ranks a NaN in `b` before one in `c`.

use super::words;
use crate::ops::float::{integral_to_i64, to_odd, two_sum};
use crate::{V128, Vscr};

const SIGN: u32 = 0x8000_0000;
const EXPONENT: u32 = 0x7F80_0000;
/// The high bit of the fraction, set in a quiet NaN.
const QUIET: u32 = 0x0040_0000;
/// 2^-126, the smallest normal single; widening it is exact.
const MIN_NORMAL: f64 = f32::MIN_POSITIVE as f64;

/// The single NaN an invalid vector operation generates: positive, quiet, no payload.
pub const VECTOR_DEFAULT_NAN: u32 = 0x7FC0_0000;

/// Whether the single `x` is a NaN.
fn is_nan(x: u32) -> bool {
    x & !SIGN > EXPONENT
}

/// The single `x` as a double, a denormal read as a zero of its sign when `nj`. `x` is not a NaN.
fn input(nj: bool, x: u32) -> f64 {
    let x = if nj && x & EXPONENT == 0 { x & SIGN } else { x };
    // Widening a single that is not a NaN is exact.
    f64::from(f32::from_bits(x))
}

/// The double `r`, the exact result or one that rounds to single as the exact result does, as a
/// single: rounded to nearest even, or a zero of its sign when `nj` and `r` is nonzero and below
/// the normal range. `r` is not a NaN.
fn output(nj: bool, r: f64) -> u32 {
    if nj && r != 0.0 && r.abs() < MIN_NORMAL {
        return if r.is_sign_negative() { SIGN } else { 0 };
    }
    // A float-to-float cast of a number rounds to nearest even, an overflow to an infinity.
    (r as f32).to_bits()
}

/// The first NaN of `operands`, quieted, if there is one.
fn first_nan(operands: &[u32]) -> Option<u32> {
    operands.iter().find(|&&x| is_nan(x)).map(|&x| x | QUIET)
}

/// One lane of an operation of two operands: the NaN rule, then `op` on the inputs, an invalid
/// operation giving the default NaN.
fn binary(nj: bool, a: u32, b: u32, op: impl Fn(f64, f64) -> f64) -> u32 {
    if let Some(nan) = first_nan(&[a, b]) {
        return nan;
    }
    let r = op(input(nj, a), input(nj, b));
    if r.is_nan() {
        VECTOR_DEFAULT_NAN
    } else {
        output(nj, r)
    }
}

/// `vaddfp`: `a + b`. For singles, rounding the double sum to single rounds the exact sum once.
#[inline]
pub fn vaddfp(vscr: Vscr, a: V128, b: V128) -> V128 {
    words(a, b, |x, y| binary(vscr.nj(), x, y, |x, y| x + y))
}

/// `vsubfp`: `a - b`.
#[inline]
pub fn vsubfp(vscr: Vscr, a: V128, b: V128) -> V128 {
    words(a, b, |x, y| binary(vscr.nj(), x, y, |x, y| x - y))
}

/// `vmulfp128`: `a × b`, rounded once; the double product of two singles is exact.
#[inline]
pub fn vmulfp128(vscr: Vscr, a: V128, b: V128) -> V128 {
    words(a, b, |x, y| binary(vscr.nj(), x, y, |x, y| x * y))
}

/// One lane of `a × c + b` with one rounding, negated when `negate`. A NaN is not negated.
fn multiply_add(nj: bool, a: u32, c: u32, b: u32, negate: bool) -> u32 {
    if let Some(nan) = first_nan(&[a, b, c]) {
        return nan;
    }
    let (a, c) = (input(nj, a), input(nj, c));
    let b = input(nj, b);
    let b = if negate { -b } else { b };
    // The product of two singles is exact in double, and so is its sum with a single's error.
    let product = a * c;
    let sum = product + b;
    if sum.is_nan() {
        // Infinity times zero, or infinities of opposite signs.
        return VECTOR_DEFAULT_NAN;
    }
    let r = if sum.is_finite() {
        let (sum, error) = two_sum(product, b);
        let tiny = sum.abs() < MIN_NORMAL
            || (sum.abs() == MIN_NORMAL && error != 0.0 && (error < 0.0) != (sum < 0.0));
        if nj && tiny && sum != 0.0 {
            let zero = if sum < 0.0 { SIGN } else { 0 };
            return if negate { zero ^ SIGN } else { zero };
        }
        // Rounded to odd in double, then to single: one rounding of the exact sum.
        output(false, to_odd(sum, error))
    } else {
        output(false, sum)
    };
    if negate { r ^ SIGN } else { r }
}

/// `vmaddfp`: `a × c + b` with one rounding (`bfp32_MULTIPLY_ADD`). `vmaddfp128 vD, vA, vB` is
/// `vmaddfp(vscr, va, vb, vd)` and `vmaddcfp128 vD, vA, vB` is `vmaddfp(vscr, va, vd, vb)`.
#[inline]
pub fn vmaddfp(vscr: Vscr, a: V128, c: V128, b: V128) -> V128 {
    V128(std::array::from_fn(|i| {
        multiply_add(vscr.nj(), a.0[i], c.0[i], b.0[i], false)
    }))
}

/// `vnmsubfp`: `-(a × c - b)`, rounded once then negated; a NaN is not negated
/// (`bfp32_NEGATIVE_MULTIPLY_SUBTRACT`). `vnmsubfp128 vD, vA, vB` is `vnmsubfp(vscr, va, vb, vd)`.
#[inline]
pub fn vnmsubfp(vscr: Vscr, a: V128, c: V128, b: V128) -> V128 {
    V128(std::array::from_fn(|i| {
        multiply_add(vscr.nj(), a.0[i], c.0[i], b.0[i], true)
    }))
}

/// One lane of the maximum (`max`) or the minimum: a NaN by the rule; +0 is above -0.
fn extremum(nj: bool, a: u32, b: u32, max: bool) -> u32 {
    if let Some(nan) = first_nan(&[a, b]) {
        return nan;
    }
    let flush = |x: u32| if nj && x & EXPONENT == 0 { x & SIGN } else { x };
    let (a, b) = (flush(a), flush(b));
    let (x, y) = (input(false, a), input(false, b));
    if x == y {
        // Equal values have equal bits, except +0 and -0: the maximum is -0 only if both are.
        if max { a & b } else { a | b }
    } else if (x > y) == max {
        a
    } else {
        b
    }
}

/// `vmaxfp`: the larger of `a` and `b`; the maximum of +0 and -0 is +0 (`bfp32_MAXIMUM`).
#[inline]
pub fn vmaxfp(vscr: Vscr, a: V128, b: V128) -> V128 {
    words(a, b, |x, y| extremum(vscr.nj(), x, y, true))
}

/// `vminfp`: the smaller of `a` and `b`; the minimum of +0 and -0 is -0 (`bfp32_MINIMUM`).
#[inline]
pub fn vminfp(vscr: Vscr, a: V128, b: V128) -> V128 {
    words(a, b, |x, y| extremum(vscr.nj(), x, y, false))
}

/// One lane of an operation of one operand: a NaN quieted, otherwise `op` on the input.
fn unary(nj: bool, b: u32, op: impl Fn(f64) -> f64) -> u32 {
    if is_nan(b) {
        return b | QUIET;
    }
    let r = op(input(nj, b));
    if r.is_nan() {
        VECTOR_DEFAULT_NAN
    } else {
        output(nj, r)
    }
}

/// Applies `op` to each lane of `b` as [`unary`] does.
fn map_unary(vscr: Vscr, b: V128, op: impl Fn(f64) -> f64) -> V128 {
    V128(b.0.map(|x| unary(vscr.nj(), x, &op)))
}

/// `vrfin`: each element rounded to the nearest integer, ties to even.
#[inline]
pub fn vrfin(vscr: Vscr, b: V128) -> V128 {
    map_unary(vscr, b, f64::round_ties_even)
}

/// `vrfiz`: each element rounded toward zero to an integer.
#[inline]
pub fn vrfiz(vscr: Vscr, b: V128) -> V128 {
    map_unary(vscr, b, f64::trunc)
}

/// `vrfip`: each element rounded toward +infinity to an integer.
#[inline]
pub fn vrfip(vscr: Vscr, b: V128) -> V128 {
    map_unary(vscr, b, f64::ceil)
}

/// `vrfim`: each element rounded toward -infinity to an integer.
#[inline]
pub fn vrfim(vscr: Vscr, b: V128) -> V128 {
    map_unary(vscr, b, f64::floor)
}

/// `vrefp`: the reciprocal of each element, rounded to single. The ISA asks for an estimate within
/// one part in 4096; this is the exact reciprocal, rounded once. ±0 give an infinity of their
/// sign, ±infinity a zero of theirs.
#[inline]
pub fn vrefp(vscr: Vscr, b: V128) -> V128 {
    map_unary(vscr, b, |x| 1.0 / x)
}

/// `vrsqrtefp`: the reciprocal square root of each element, rounded to single. ±0 give an
/// infinity of their sign, +infinity +0, and a negative number the default NaN.
#[inline]
pub fn vrsqrtefp(vscr: Vscr, b: V128) -> V128 {
    map_unary(vscr, b, |x| if x == 0.0 { 1.0 / x } else { 1.0 / x.sqrt() })
}

/// `vexptefp`: 2 raised to each element, rounded to single; exact for an integral element whose
/// power is representable. -infinity gives +0 and ±0 give 1.
#[inline]
pub fn vexptefp(vscr: Vscr, b: V128) -> V128 {
    map_unary(vscr, b, exp2)
}

/// `vlogefp`: the base 2 logarithm of each element, rounded to single; exact for a power of 2.
/// ±0 give -infinity, and a negative number the default NaN.
#[inline]
pub fn vlogefp(vscr: Vscr, b: V128) -> V128 {
    map_unary(vscr, b, log2)
}

/// 2^`x` for a single `x` that is not a NaN, with basic double operations only, so that the
/// result is the same on every host. The error is a few units in the last place of a double.
fn exp2(x: f64) -> f64 {
    if x >= 128.0 {
        return f64::INFINITY;
    }
    if x < -152.0 {
        // Below half the smallest single denormal: rounds to +0.
        return 0.0;
    }
    // x = n + f with |f| <= 1/2, both exact: x has at most 24 significant bits.
    let n = x.round_ties_even();
    let t = (x - n) * std::f64::consts::LN_2;
    // e^t by its Taylor series, which for |t| <= 0.35 is below 2^-70 after 17 terms.
    let mut sum = 1.0;
    for k in (1..=17).rev() {
        sum = 1.0 + sum * t / f64::from(k);
    }
    sum * power_of_two(integral_to_i64(n))
}

/// 2^`n` for `n` in [-152, 127], exact.
fn power_of_two(n: i64) -> f64 {
    // The biased exponent of a normal double, which these powers all are.
    let biased = u64::try_from(n + 1023).unwrap_or(0);
    f64::from_bits(biased << 52)
}

/// log2(`x`) for a single `x` that is not a NaN, with basic double operations only. Exact when
/// `x` is a power of 2; otherwise within a few units in the last place of a double.
fn log2(x: f64) -> f64 {
    if x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return f64::INFINITY;
    }
    // x = m × 2^e with m in [1, 2): every single, denormals included, is a normal double.
    let bits = x.to_bits();
    // The mask leaves the 11 bits of the exponent, so the cast loses nothing.
    let mut e = ((bits >> 52) & 0x7FF) as i32 - 1023;
    let mut m = f64::from_bits((bits & 0x000F_FFFF_FFFF_FFFF) | 0x3FF0_0000_0000_0000);
    if m > std::f64::consts::SQRT_2 {
        m /= 2.0;
        e += 1;
    }
    // ln m = 2 atanh(s), s = (m - 1) / (m + 1), |s| <= 0.172: the series is below 2^-70 after
    // 12 terms. m - 1 is exact.
    let s = (m - 1.0) / (m + 1.0);
    let s2 = s * s;
    let mut sum = 0.0;
    for k in (0..12).rev() {
        sum = 1.0 / f64::from(2 * k + 1) + s2 * sum;
    }
    f64::from(e) + 2.0 * s * sum * std::f64::consts::LOG2_E
}

/// `vcfsx`: each word as a signed integer, divided by 2^`uim` and rounded to single. Dividing by a
/// power of 2 is exact, so the result rounds once.
#[inline]
pub fn vcfsx(b: V128, uim: u8) -> V128 {
    let scale = power_of_two(-i64::from(uim & 31));
    // The bits of each word are a two's complement integer.
    V128(b.0.map(|x| ((f64::from(x as i32) * scale) as f32).to_bits()))
}

/// `vcfux`: each word as an unsigned integer, divided by 2^`uim` and rounded to single.
#[inline]
pub fn vcfux(b: V128, uim: u8) -> V128 {
    let scale = power_of_two(-i64::from(uim & 31));
    V128(b.0.map(|x| ((f64::from(x) * scale) as f32).to_bits()))
}

/// 2^31 as a double.
const TWO_31: f64 = 2_147_483_648.0;
/// 2^32 as a double.
const TWO_32: f64 = 4_294_967_296.0;

/// `vctsxs`: each element times 2^`uim`, truncated to a signed word (`si32_CONVERT_FROM_BFP32`).
/// Out of range or infinite, the bound of its sign, setting SAT; a NaN gives 0 and leaves SAT.
#[inline]
pub fn vctsxs(vscr: &mut Vscr, b: V128, uim: u8) -> V128 {
    let scale = power_of_two(i64::from(uim & 31));
    let mut saturated = false;
    let r = V128(b.0.map(|x| {
        if is_nan(x) {
            return 0;
        }
        // A denormal times at most 2^31 truncates to zero, so NJ does not matter here.
        let t = (input(false, x) * scale).trunc();
        let value = if t >= TWO_31 {
            saturated = true;
            i32::MAX
        } else if t < -TWO_31 {
            saturated = true;
            i32::MIN
        } else {
            // In range, so the cast to the low word loses nothing.
            integral_to_i64(t) as i32
        };
        // The bits of the two's complement are the word.
        value as u32
    }));
    vscr.saturate_if(saturated);
    r
}

/// `vctuxs`: each element times 2^`uim`, truncated to an unsigned word
/// (`ui32_CONVERT_FROM_BFP32`). Above the range or +infinity, `0xFFFF_FFFF`; a negative value whose
/// truncation is not zero, or -infinity, gives 0; both set SAT. A NaN gives 0 and leaves SAT.
#[inline]
pub fn vctuxs(vscr: &mut Vscr, b: V128, uim: u8) -> V128 {
    let scale = power_of_two(i64::from(uim & 31));
    let mut saturated = false;
    let r = V128(b.0.map(|x| {
        if is_nan(x) {
            return 0;
        }
        let t = (input(false, x) * scale).trunc();
        if t >= TWO_32 {
            saturated = true;
            u32::MAX
        } else if t < 0.0 {
            saturated = true;
            0
        } else {
            // In range and not negative, so the cast to the low word loses nothing.
            integral_to_i64(t) as u32
        }
    }));
    vscr.saturate_if(saturated);
    r
}

/// One lane of a compare: all ones if `holds` of the inputs, zeros otherwise or for a NaN.
fn compare(nj: bool, a: u32, b: u32, holds: impl Fn(f64, f64) -> bool) -> u32 {
    if is_nan(a) || is_nan(b) {
        return 0;
    }
    if holds(input(nj, a), input(nj, b)) {
        u32::MAX
    } else {
        0
    }
}

/// `vcmpeqfp`: all ones where `a == b`; +0 equals -0, and with NJ a denormal equals zero.
#[inline]
pub fn vcmpeqfp(vscr: Vscr, a: V128, b: V128) -> V128 {
    words(a, b, |x, y| compare(vscr.nj(), x, y, |x, y| x == y))
}

/// `vcmpgefp`: all ones where `a >= b`.
#[inline]
pub fn vcmpgefp(vscr: Vscr, a: V128, b: V128) -> V128 {
    words(a, b, |x, y| compare(vscr.nj(), x, y, |x, y| x >= y))
}

/// `vcmpgtfp`: all ones where `a > b`.
#[inline]
pub fn vcmpgtfp(vscr: Vscr, a: V128, b: V128) -> V128 {
    words(a, b, |x, y| compare(vscr.nj(), x, y, |x, y| x > y))
}

/// `vcmpbfp`: bit 0 of each word set when `a <= b` is false, bit 1 when `a >= -b` is false, so a
/// NaN in either gives `0xC000_0000`.
#[inline]
pub fn vcmpbfp(vscr: Vscr, a: V128, b: V128) -> V128 {
    words(a, b, |x, y| {
        if is_nan(x) || is_nan(y) {
            return 0xC000_0000;
        }
        let (x, y) = (input(vscr.nj(), x), input(vscr.nj(), y));
        let above = if x <= y { 0 } else { 0x8000_0000 };
        let below = if x >= -y { 0 } else { 0x4000_0000 };
        above | below
    })
}

/// The dot product of the first `n` words of `a` and `b`, in all four words: products exact in
/// double, added in word order, rounded once.
fn dot(vscr: Vscr, a: V128, b: V128, n: usize) -> V128 {
    let nj = vscr.nj();
    let mut operands = [0; 8];
    for i in 0..n {
        operands[2 * i] = a.0[i];
        operands[2 * i + 1] = b.0[i];
    }
    let lane = match first_nan(&operands[..2 * n]) {
        Some(nan) => nan,
        None => {
            let mut sum = 0.0;
            for i in 0..n {
                sum += input(nj, a.0[i]) * input(nj, b.0[i]);
            }
            if sum.is_nan() {
                VECTOR_DEFAULT_NAN
            } else {
                output(nj, sum)
            }
        }
    };
    V128([lane; 4])
}

/// `vmsum3fp128`: the dot product of words 0 to 2 of `a` and `b`, in every word.
#[inline]
pub fn vmsum3fp128(vscr: Vscr, a: V128, b: V128) -> V128 {
    dot(vscr, a, b, 3)
}

/// `vmsum4fp128`: the dot product of the four words of `a` and `b`, in every word.
#[inline]
pub fn vmsum4fp128(vscr: Vscr, a: V128, b: V128) -> V128 {
    dot(vscr, a, b, 4)
}
