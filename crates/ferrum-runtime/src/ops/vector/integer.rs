// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The vector integer instructions: arithmetic, saturation, averages, extremes, multiplies,
//! sums, logic, shifts, rotates and compares.
//!
//! Elements are numbered from 0, the most significant. A saturating helper takes the [`Vscr`] and
//! sets SAT when any element saturates; SAT is sticky. A shift or rotate by element takes its
//! count from the low bits of the matching element of vB, modulo the element size.

use super::{bytes, halfwords, words};
use crate::{V128, Vscr};

/// `value` clamped to `[min, max]`, recording in `saturated` whether it was outside.
fn clamp(value: i64, min: i64, max: i64, saturated: &mut bool) -> i64 {
    if value < min {
        *saturated = true;
        min
    } else if value > max {
        *saturated = true;
        max
    } else {
        value
    }
}

// The typed clamps: each cast keeps a value the clamp already put in range.
pub(super) fn sat_u8(value: i64, saturated: &mut bool) -> u8 {
    clamp(value, 0, 0xFF, saturated) as u8
}
pub(super) fn sat_i8(value: i64, saturated: &mut bool) -> u8 {
    clamp(value, -0x80, 0x7F, saturated) as i8 as u8
}
pub(super) fn sat_u16(value: i64, saturated: &mut bool) -> u16 {
    clamp(value, 0, 0xFFFF, saturated) as u16
}
pub(super) fn sat_i16(value: i64, saturated: &mut bool) -> u16 {
    clamp(value, -0x8000, 0x7FFF, saturated) as i16 as u16
}
pub(super) fn sat_u32(value: i64, saturated: &mut bool) -> u32 {
    clamp(value, 0, 0xFFFF_FFFF, saturated) as u32
}
pub(super) fn sat_i32(value: i64, saturated: &mut bool) -> u32 {
    clamp(value, -0x8000_0000, 0x7FFF_FFFF, saturated) as i32 as u32
}

// Sign extensions of element bits; the casts reinterpret the bits as two's complement.
fn s8(x: u8) -> i64 {
    i64::from(x as i8)
}
pub(super) fn s16(x: u16) -> i64 {
    i64::from(x as i16)
}
pub(super) fn s32(x: u32) -> i64 {
    i64::from(x as i32)
}

/// Runs `op` with a SAT flag, then records it in `vscr`.
pub(super) fn saturating(vscr: &mut Vscr, op: impl FnOnce(&mut bool) -> V128) -> V128 {
    let mut saturated = false;
    let r = op(&mut saturated);
    vscr.saturate_if(saturated);
    r
}

/// Defines modulo helpers: `name(a, b)` applies `op` to each element pair of the lane helper.
macro_rules! modulo {
    ($($(#[$doc:meta])* $name:ident = $lanes:ident, |$x:ident, $y:ident| $body:expr;)*) => {$(
        $(#[$doc])*
        #[inline]
        pub fn $name(a: V128, b: V128) -> V128 {
            $lanes(a, b, |$x, $y| $body)
        }
    )*};
}

/// Defines saturating helpers: `name(vscr, a, b)` clamps each `op` result with `clamp`.
macro_rules! saturate {
    ($($(#[$doc:meta])* $name:ident = $lanes:ident, $clamp:ident, |$x:ident, $y:ident| $body:expr;)*) => {$(
        $(#[$doc])*
        #[inline]
        pub fn $name(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
            saturating(vscr, |sat| $lanes(a, b, |$x, $y| $clamp($body, sat)))
        }
    )*};
}

// In the averages the casts keep a value the shift put in range; in the arithmetic shifts they
// reinterpret the bits as signed and back.
modulo! {
    /// `vaddubm`: bytes added modulo 2^8.
    vaddubm = bytes, |x, y| x.wrapping_add(y);
    /// `vadduhm`: halfwords added modulo 2^16.
    vadduhm = halfwords, |x, y| x.wrapping_add(y);
    /// `vadduwm`: words added modulo 2^32.
    vadduwm = words, |x, y| x.wrapping_add(y);
    /// `vsububm`: bytes subtracted modulo 2^8.
    vsububm = bytes, |x, y| x.wrapping_sub(y);
    /// `vsubuhm`: halfwords subtracted modulo 2^16.
    vsubuhm = halfwords, |x, y| x.wrapping_sub(y);
    /// `vsubuwm`: words subtracted modulo 2^32.
    vsubuwm = words, |x, y| x.wrapping_sub(y);
    /// `vaddcuw`: the carry out of each word sum, 1 or 0.
    vaddcuw = words, |x, y| u32::from(x.checked_add(y).is_none());
    /// `vsubcuw`: the carry out of each word difference: 1 when it does not borrow.
    vsubcuw = words, |x, y| u32::from(x >= y);
    /// `vavgub`: the rounded average of unsigned bytes.
    vavgub = bytes, |x, y| ((u16::from(x) + u16::from(y) + 1) >> 1) as u8;
    /// `vavguh`: the rounded average of unsigned halfwords.
    vavguh = halfwords, |x, y| ((u32::from(x) + u32::from(y) + 1) >> 1) as u16;
    /// `vavguw`: the rounded average of unsigned words.
    vavguw = words, |x, y| ((u64::from(x) + u64::from(y) + 1) >> 1) as u32;
    /// `vavgsb`: the rounded average of signed bytes.
    vavgsb = bytes, |x, y| ((s8(x) + s8(y) + 1) >> 1) as u8;
    /// `vavgsh`: the rounded average of signed halfwords.
    vavgsh = halfwords, |x, y| ((s16(x) + s16(y) + 1) >> 1) as u16;
    /// `vavgsw`: the rounded average of signed words.
    vavgsw = words, |x, y| ((s32(x) + s32(y) + 1) >> 1) as u32;
    /// `vmaxub`: the larger unsigned byte.
    vmaxub = bytes, |x, y| x.max(y);
    /// `vmaxuh`: the larger unsigned halfword.
    vmaxuh = halfwords, |x, y| x.max(y);
    /// `vmaxuw`: the larger unsigned word.
    vmaxuw = words, |x, y| x.max(y);
    /// `vmaxsb`: the larger signed byte.
    vmaxsb = bytes, |x, y| if s8(x) >= s8(y) { x } else { y };
    /// `vmaxsh`: the larger signed halfword.
    vmaxsh = halfwords, |x, y| if s16(x) >= s16(y) { x } else { y };
    /// `vmaxsw`: the larger signed word.
    vmaxsw = words, |x, y| if s32(x) >= s32(y) { x } else { y };
    /// `vminub`: the smaller unsigned byte.
    vminub = bytes, |x, y| x.min(y);
    /// `vminuh`: the smaller unsigned halfword.
    vminuh = halfwords, |x, y| x.min(y);
    /// `vminuw`: the smaller unsigned word.
    vminuw = words, |x, y| x.min(y);
    /// `vminsb`: the smaller signed byte.
    vminsb = bytes, |x, y| if s8(x) <= s8(y) { x } else { y };
    /// `vminsh`: the smaller signed halfword.
    vminsh = halfwords, |x, y| if s16(x) <= s16(y) { x } else { y };
    /// `vminsw`: the smaller signed word.
    vminsw = words, |x, y| if s32(x) <= s32(y) { x } else { y };
    /// `vand`: the bitwise AND.
    vand = words, |x, y| x & y;
    /// `vandc`: `a` AND NOT `b`.
    vandc = words, |x, y| x & !y;
    /// `vor`: the bitwise OR.
    vor = words, |x, y| x | y;
    /// `vxor`: the bitwise XOR.
    vxor = words, |x, y| x ^ y;
    /// `vnor`: the bitwise NOR.
    vnor = words, |x, y| !(x | y);
    /// `vrlb`: each byte rotated left by the low 3 bits of the byte of `b`.
    vrlb = bytes, |x, y| x.rotate_left(u32::from(y & 7));
    /// `vrlh`: each halfword rotated left by the low 4 bits of the halfword of `b`.
    vrlh = halfwords, |x, y| x.rotate_left(u32::from(y & 15));
    /// `vrlw`: each word rotated left by the low 5 bits of the word of `b`.
    vrlw = words, |x, y| x.rotate_left(y & 31);
    /// `vslb`: each byte shifted left by the low 3 bits of the byte of `b`.
    vslb = bytes, |x, y| x << (y & 7);
    /// `vslh`: each halfword shifted left by the low 4 bits of the halfword of `b`.
    vslh = halfwords, |x, y| x << (y & 15);
    /// `vslw`: each word shifted left by the low 5 bits of the word of `b`.
    vslw = words, |x, y| x << (y & 31);
    /// `vsrb`: each byte shifted right, filling with zeros.
    vsrb = bytes, |x, y| x >> (y & 7);
    /// `vsrh`: each halfword shifted right, filling with zeros.
    vsrh = halfwords, |x, y| x >> (y & 15);
    /// `vsrw`: each word shifted right, filling with zeros.
    vsrw = words, |x, y| x >> (y & 31);
    /// `vsrab`: each byte shifted right, filling with its sign.
    vsrab = bytes, |x, y| ((x as i8) >> (y & 7)) as u8;
    /// `vsrah`: each halfword shifted right, filling with its sign.
    vsrah = halfwords, |x, y| ((x as i16) >> (y & 15)) as u16;
    /// `vsraw`: each word shifted right, filling with its sign.
    vsraw = words, |x, y| ((x as i32) >> (y & 31)) as u32;
    /// `vcmpequb`: all ones where the bytes are equal.
    vcmpequb = bytes, |x, y| if x == y { 0xFF } else { 0 };
    /// `vcmpequh`: all ones where the halfwords are equal.
    vcmpequh = halfwords, |x, y| if x == y { 0xFFFF } else { 0 };
    /// `vcmpequw`: all ones where the words are equal.
    vcmpequw = words, |x, y| if x == y { u32::MAX } else { 0 };
    /// `vcmpgtub`: all ones where the unsigned byte of `a` is greater.
    vcmpgtub = bytes, |x, y| if x > y { 0xFF } else { 0 };
    /// `vcmpgtuh`: all ones where the unsigned halfword of `a` is greater.
    vcmpgtuh = halfwords, |x, y| if x > y { 0xFFFF } else { 0 };
    /// `vcmpgtuw`: all ones where the unsigned word of `a` is greater.
    vcmpgtuw = words, |x, y| if x > y { u32::MAX } else { 0 };
    /// `vcmpgtsb`: all ones where the signed byte of `a` is greater.
    vcmpgtsb = bytes, |x, y| if s8(x) > s8(y) { 0xFF } else { 0 };
    /// `vcmpgtsh`: all ones where the signed halfword of `a` is greater.
    vcmpgtsh = halfwords, |x, y| if s16(x) > s16(y) { 0xFFFF } else { 0 };
    /// `vcmpgtsw`: all ones where the signed word of `a` is greater.
    vcmpgtsw = words, |x, y| if s32(x) > s32(y) { u32::MAX } else { 0 };
}

saturate! {
    /// `vaddubs`: unsigned bytes added, saturated.
    vaddubs = bytes, sat_u8, |x, y| i64::from(x) + i64::from(y);
    /// `vaddsbs`: signed bytes added, saturated.
    vaddsbs = bytes, sat_i8, |x, y| s8(x) + s8(y);
    /// `vadduhs`: unsigned halfwords added, saturated.
    vadduhs = halfwords, sat_u16, |x, y| i64::from(x) + i64::from(y);
    /// `vaddshs`: signed halfwords added, saturated.
    vaddshs = halfwords, sat_i16, |x, y| s16(x) + s16(y);
    /// `vadduws`: unsigned words added, saturated.
    vadduws = words, sat_u32, |x, y| i64::from(x) + i64::from(y);
    /// `vaddsws`: signed words added, saturated.
    vaddsws = words, sat_i32, |x, y| s32(x) + s32(y);
    /// `vsububs`: unsigned bytes subtracted, saturated.
    vsububs = bytes, sat_u8, |x, y| i64::from(x) - i64::from(y);
    /// `vsubsbs`: signed bytes subtracted, saturated.
    vsubsbs = bytes, sat_i8, |x, y| s8(x) - s8(y);
    /// `vsubuhs`: unsigned halfwords subtracted, saturated.
    vsubuhs = halfwords, sat_u16, |x, y| i64::from(x) - i64::from(y);
    /// `vsubshs`: signed halfwords subtracted, saturated.
    vsubshs = halfwords, sat_i16, |x, y| s16(x) - s16(y);
    /// `vsubuws`: unsigned words subtracted, saturated.
    vsubuws = words, sat_u32, |x, y| i64::from(x) - i64::from(y);
    /// `vsubsws`: signed words subtracted, saturated.
    vsubsws = words, sat_i32, |x, y| s32(x) - s32(y);
}

/// The products of the even (`odd` false) or odd elements of `a` and `b`, as `N`-byte elements
/// widened to `2N` bytes, read from big-endian bytes.
fn multiply<const N: usize>(a: V128, b: V128, odd: bool, signed: bool) -> V128 {
    let (a, b) = (a.to_bytes(), b.to_bytes());
    let element = |bytes: &[u8; 16], i: usize| -> i64 {
        let at = (2 * i + usize::from(odd)) * N;
        let value = bytes[at..at + N]
            .iter()
            .fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
        if signed {
            // Sign-extends the N-byte value.
            let shift = 64 - 8 * N as u32;
            ((value << shift) as i64) >> shift
        } else {
            // At most 16 bits, which the cast keeps.
            value as i64
        }
    };
    let mut out = [0u8; 16];
    for i in 0..8 / N {
        let product = element(&a, i).wrapping_mul(element(&b, i));
        // The low 2N bytes of the product, which hold it exactly.
        let product = (product as u64).to_be_bytes();
        out[2 * N * i..2 * N * (i + 1)].copy_from_slice(&product[8 - 2 * N..]);
    }
    V128::from_bytes(out)
}

/// `vmuleub`: products of the even unsigned bytes, as halfwords.
#[inline]
pub fn vmuleub(a: V128, b: V128) -> V128 {
    multiply::<1>(a, b, false, false)
}

/// `vmulesb`: products of the even signed bytes, as halfwords.
#[inline]
pub fn vmulesb(a: V128, b: V128) -> V128 {
    multiply::<1>(a, b, false, true)
}

/// `vmuloub`: products of the odd unsigned bytes, as halfwords.
#[inline]
pub fn vmuloub(a: V128, b: V128) -> V128 {
    multiply::<1>(a, b, true, false)
}

/// `vmulosb`: products of the odd signed bytes, as halfwords.
#[inline]
pub fn vmulosb(a: V128, b: V128) -> V128 {
    multiply::<1>(a, b, true, true)
}

/// `vmuleuh`: products of the even unsigned halfwords, as words.
#[inline]
pub fn vmuleuh(a: V128, b: V128) -> V128 {
    multiply::<2>(a, b, false, false)
}

/// `vmulesh`: products of the even signed halfwords, as words.
#[inline]
pub fn vmulesh(a: V128, b: V128) -> V128 {
    multiply::<2>(a, b, false, true)
}

/// `vmulouh`: products of the odd unsigned halfwords, as words.
#[inline]
pub fn vmulouh(a: V128, b: V128) -> V128 {
    multiply::<2>(a, b, true, false)
}

/// `vmulosh`: products of the odd signed halfwords, as words.
#[inline]
pub fn vmulosh(a: V128, b: V128) -> V128 {
    multiply::<2>(a, b, true, true)
}

/// Applies `op` to each halfword of `a`, `b` and `c`.
fn halfwords3(a: V128, b: V128, c: V128, mut op: impl FnMut(u16, u16, u16) -> u16) -> V128 {
    let (a, b, c) = (a.halfwords(), b.halfwords(), c.halfwords());
    V128::from_halfwords(std::array::from_fn(|i| op(a[i], b[i], c[i])))
}

/// `vmhaddshs`: the high half of each signed product (shifted right 15), plus `c`, saturated.
#[inline]
pub fn vmhaddshs(vscr: &mut Vscr, a: V128, b: V128, c: V128) -> V128 {
    saturating(vscr, |sat| {
        halfwords3(a, b, c, |x, y, z| {
            sat_i16(((s16(x) * s16(y)) >> 15) + s16(z), sat)
        })
    })
}

/// `vmhraddshs`: as [`vmhaddshs`], with the product rounded (`+ 0x4000`) before the shift.
#[inline]
pub fn vmhraddshs(vscr: &mut Vscr, a: V128, b: V128, c: V128) -> V128 {
    saturating(vscr, |sat| {
        halfwords3(a, b, c, |x, y, z| {
            sat_i16(((s16(x) * s16(y) + 0x4000) >> 15) + s16(z), sat)
        })
    })
}

/// `vmladduhm`: `a × b + c` per halfword, modulo 2^16.
#[inline]
pub fn vmladduhm(a: V128, b: V128, c: V128) -> V128 {
    halfwords3(a, b, c, |x, y, z| x.wrapping_mul(y).wrapping_add(z))
}

/// The sum, for each word, of `c` and the products of the `N`-byte elements of `a` and `b` in
/// that word, with `a` signed if `signed_a` and `b` if `signed_b`; `finish` turns the 64-bit sum
/// into the word.
fn multiply_sum<const N: usize>(
    a: V128,
    b: V128,
    c: V128,
    signed: (bool, bool),
    mut finish: impl FnMut(i64) -> u32,
) -> V128 {
    let (a, b) = (a.to_bytes(), b.to_bytes());
    let element = |bytes: &[u8; 16], i: usize, signed: bool| -> i64 {
        let value = bytes[i * N..(i + 1) * N]
            .iter()
            .fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
        let shift = 64 - 8 * N as u32;
        // Sign- or zero-extends the N-byte value.
        if signed {
            ((value << shift) as i64) >> shift
        } else {
            value as i64
        }
    };
    let per_word = 4 / N;
    V128(std::array::from_fn(|w| {
        let base = if signed.0 || signed.1 {
            s32(c.0[w])
        } else {
            i64::from(c.0[w])
        };
        let sum = (0..per_word).fold(base, |acc, k| {
            let i = w * per_word + k;
            acc + element(&a, i, signed.0) * element(&b, i, signed.1)
        });
        finish(sum)
    }))
}

/// The low word of a sum, which the modulo forms keep.
fn low_word(sum: i64) -> u32 {
    // Truncation to the low word is the modulo.
    sum as u32
}

/// `vmsumubm`: each word of `c` plus the products of its four unsigned bytes, modulo 2^32.
#[inline]
pub fn vmsumubm(a: V128, b: V128, c: V128) -> V128 {
    multiply_sum::<1>(a, b, c, (false, false), low_word)
}

/// `vmsummbm`: each word of `c` plus the products of the signed bytes of `a` and the unsigned
/// bytes of `b`, modulo 2^32.
#[inline]
pub fn vmsummbm(a: V128, b: V128, c: V128) -> V128 {
    multiply_sum::<1>(a, b, c, (true, false), low_word)
}

/// `vmsumuhm`: each word of `c` plus the products of its two unsigned halfwords, modulo 2^32.
#[inline]
pub fn vmsumuhm(a: V128, b: V128, c: V128) -> V128 {
    multiply_sum::<2>(a, b, c, (false, false), low_word)
}

/// `vmsumuhs`: as [`vmsumuhm`], saturated to an unsigned word.
#[inline]
pub fn vmsumuhs(vscr: &mut Vscr, a: V128, b: V128, c: V128) -> V128 {
    saturating(vscr, |sat| {
        multiply_sum::<2>(a, b, c, (false, false), |s| sat_u32(s, sat))
    })
}

/// `vmsumshm`: each signed word of `c` plus the products of its two signed halfwords, modulo
/// 2^32.
#[inline]
pub fn vmsumshm(a: V128, b: V128, c: V128) -> V128 {
    multiply_sum::<2>(a, b, c, (true, true), low_word)
}

/// `vmsumshs`: as [`vmsumshm`], saturated to a signed word.
#[inline]
pub fn vmsumshs(vscr: &mut Vscr, a: V128, b: V128, c: V128) -> V128 {
    saturating(vscr, |sat| {
        multiply_sum::<2>(a, b, c, (true, true), |s| sat_i32(s, sat))
    })
}

/// `vsumsws`: word 3 of `b` plus the four signed words of `a`, saturated, in word 3; words 0 to 2
/// are zero.
#[inline]
pub fn vsumsws(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    saturating(vscr, |sat| {
        let sum = a.0.iter().map(|&x| s32(x)).sum::<i64>() + s32(b.0[3]);
        V128([0, 0, 0, sat_i32(sum, sat)])
    })
}

/// `vsum2sws`: words 1 and 3 of `b` plus the signed words 0 and 1, and 2 and 3, of `a`, saturated,
/// in words 1 and 3; words 0 and 2 are zero.
#[inline]
pub fn vsum2sws(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    saturating(vscr, |sat| {
        let pair = |i: usize, sat: &mut bool| {
            sat_i32(s32(a.0[i]) + s32(a.0[i + 1]) + s32(b.0[i + 1]), sat)
        };
        let low = pair(0, sat);
        let high = pair(2, sat);
        V128([0, low, 0, high])
    })
}

/// `vsum4ubs`: each word of `b` plus the four unsigned bytes of `a` in that word, saturated.
#[inline]
pub fn vsum4ubs(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    let ones = V128::from_bytes([1; 16]);
    saturating(vscr, |sat| {
        multiply_sum::<1>(a, ones, b, (false, false), |s| sat_u32(s, sat))
    })
}

/// `vsum4sbs`: each signed word of `b` plus the four signed bytes of `a` in that word, saturated.
#[inline]
pub fn vsum4sbs(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    let ones = V128::from_bytes([1; 16]);
    saturating(vscr, |sat| {
        multiply_sum::<1>(a, ones, b, (true, false), |s| sat_i32(s, sat))
    })
}

/// `vsum4shs`: each signed word of `b` plus the two signed halfwords of `a` in that word,
/// saturated.
#[inline]
pub fn vsum4shs(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    let ones = V128::from_halfwords([1; 8]);
    saturating(vscr, |sat| {
        multiply_sum::<2>(a, ones, b, (true, false), |s| sat_i32(s, sat))
    })
}

/// The CR6 field of a vector compare with Rc = 1: `0b1000` if every element compared true (the
/// result is all ones), `0b0010` if none did (all zeros), zero otherwise.
#[inline]
pub fn vcmp_cr6(result: V128) -> u8 {
    if result.0 == [u32::MAX; 4] {
        0b1000
    } else if result == V128::ZERO {
        0b0010
    } else {
        0
    }
}

/// The CR6 field of `vcmpbfp.`: `0b0010` if every element is within its bounds (the result is
/// zero), zero otherwise.
#[inline]
pub fn vcmpbfp_cr6(result: V128) -> u8 {
    if result == V128::ZERO { 0b0010 } else { 0 }
}
