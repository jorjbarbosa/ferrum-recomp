// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The VMX128 graphics packs `vpkd3d128` and `vupkd3d128`.
//!
//! No public document defines them. Their meaning follows Xenia's emitter and the pack and unpack
//! sequences of its x64 backend at `95a5c3ee` (`src/xenia/cpu/ppc/ppc_emit_altivec.cc`,
//! `src/xenia/cpu/backend/x64/x64_seq_vector.cc`), which the expected values of the suite
//! confirm. Most formats hold an integer n in a float biased by 3.0, 3.0 + n × 2^-22, so that the
//! integer is in the low bits of the mantissa.

use crate::V128;

/// 3.0, the bias of the integer formats.
const THREE: u32 = 0x4040_0000;
/// 1.0.
const ONE: u32 = 0x3F80_0000;
/// The quiet NaN an unpack gives for the most negative value of a signed field.
const NAN: u32 = 0x7FC0_0000;

/// `x` clamped to the floats `[low, high]`, both positive, a NaN taking `low`.
fn clamp(x: u32, low: u32, high: u32) -> u32 {
    let value = f32::from_bits(x);
    if value.is_nan() || value < f32::from_bits(low) {
        low
    } else if value > f32::from_bits(high) {
        high
    } else {
        x
    }
}

/// The single `x` as a half, rounded toward zero. A NaN stays a NaN, quiet, with the top 10 bits
/// of its payload; a value above the half range gives the largest half; an infinity stays one.
pub(crate) fn single_to_half(x: u32) -> u16 {
    // Each cast below keeps a value the shifts and masks put in range.
    let sign = ((x >> 16) & 0x8000) as u16;
    let exponent = (x >> 23) & 0xFF;
    let fraction = x & 0x007F_FFFF;
    if exponent == 0xFF {
        return if fraction == 0 {
            sign | 0x7C00
        } else {
            sign | 0x7E00 | (fraction >> 13) as u16
        };
    }
    if exponent > 142 {
        // At least 2^16, above the largest half, 65504.
        return sign | 0x7BFF;
    }
    if exponent >= 113 {
        // A normal half: rebias the exponent and drop 13 fraction bits.
        return sign | ((exponent - 112) << 10) as u16 | (fraction >> 13) as u16;
    }
    if exponent == 0 {
        // A single denormal is far below the smallest half.
        return sign;
    }
    // A half denormal, m × 2^-24, or zero: the significand shifted down.
    let significand = 0x0080_0000 | fraction;
    let shift = 126 - exponent;
    sign | significand.checked_shr(shift).unwrap_or(0) as u16
}

/// The half `h` as a single, exactly. A NaN keeps its payload.
pub(crate) fn half_to_single(h: u16) -> u32 {
    let sign = u32::from(h & 0x8000) << 16;
    let exponent = u32::from((h >> 10) & 0x1F);
    let fraction = u32::from(h & 0x03FF);
    match (exponent, fraction) {
        (0x1F, _) => sign | 0x7F80_0000 | (fraction << 13),
        (0, 0) => sign,
        (0, _) => {
            // fraction × 2^-24, normalized: its top bit p gives 2^(p - 24).
            let p = 31 - fraction.leading_zeros();
            sign | ((p + 103) << 23) | ((fraction << (23 - p)) & 0x007F_FFFF)
        }
        _ => sign | ((exponent + 112) << 23) | (fraction << 13),
    }
}

/// The packed words of `b` for `kind`: words 2 and 3, word 2 zero for a format of one word.
fn pack(b: V128, kind: u8) -> [u32; 2] {
    let [x, y, z, w] = b.0;
    let short = |v: u32| clamp(v, 0x403F_8001, 0x4040_7FFF) & 0xFFFF;
    let half = |v: u32| u32::from(single_to_half(v));
    match kind {
        0 => {
            let byte = |v: u32| clamp(v, THREE, 0x4040_00FF) & 0xFF;
            [0, byte(w) << 24 | byte(x) << 16 | byte(y) << 8 | byte(z)]
        }
        1 => [0, short(x) << 16 | short(y)],
        2 => {
            let ten = |v: u32| clamp(v, 0x403F_FE01, 0x4040_01FF) & 0x3FF;
            let two = clamp(w, THREE, 0x4040_0003) & 3;
            [0, two << 30 | ten(z) << 20 | ten(y) << 10 | ten(x)]
        }
        3 => [0, half(x) << 16 | half(y)],
        4 => [short(x) << 16 | short(y), short(z) << 16 | short(w)],
        5 => [half(x) << 16 | half(y), half(z) << 16 | half(w)],
        _ => unsupported("vpkd3d128", kind),
    }
}

/// `vpkd3d128 vD, vB, kind, mask, shift`: packs `b` and places the packed words into `d`. Mask 1
/// puts the packed word in word `3 - shift`; masks 2 and 3 put the two packed words in words
/// `2 - shift` and `3 - shift`, except that with shift 3 mask 2 puts the second in word 0 and mask
/// 3 the first in word 3. The other words keep `d`'s.
///
/// Kinds 0 to 5 are `D3DCOLOR`, `SHORT_2`, `2_10_10_10`, `FLOAT16_2`, `SHORT_4` and `FLOAT16_4`.
/// Panics for another kind or mask 0, which codegen reports as opcodes without `emit_*`.
#[inline]
pub fn vpkd3d128(d: V128, b: V128, kind: u8, mask: u8, shift: u8) -> V128 {
    let [first, second] = pack(b, kind);
    let mut out = d.0;
    match (mask, shift & 3) {
        (0, _) => unsupported("vpkd3d128 mask", 0),
        (1, shift) => out[usize::from(3 - shift)] = second,
        (2, 3) => out[0] = second,
        (_, 3) => out[3] = first,
        (_, shift) => {
            out[usize::from(2 - shift)] = first;
            out[usize::from(3 - shift)] = second;
        }
    }
    V128(out)
}

/// A signed `bits`-bit field biased by 3.0, or the NaN for its most negative value.
fn biased(field: u32, bits: u32) -> u32 {
    let shift = 32 - bits;
    // Sign-extends the field by shifting it to the top and back.
    let value = ((field << shift) as i32) >> shift;
    if value == -(1 << (bits - 1)) {
        NAN
    } else {
        THREE.wrapping_add_signed(value)
    }
}

/// `vupkd3d128 vD, vB, kind`: unpacks word 3 of `b`, or words 2 and 3, as [`vpkd3d128`] packs
/// them. `D3DCOLOR` gives 1.0 + n × 2^-23 per byte; the `2_10_10_10` W gives 1.0 + n × 2^-23.
/// Panics for a kind above 5, which codegen reports as an opcode without `emit_*`.
#[inline]
pub fn vupkd3d128(b: V128, kind: u8) -> V128 {
    let (w2, w3) = (b.0[2], b.0[3]);
    let short = |word: u32, high: bool| biased(if high { word >> 16 } else { word }, 16);
    // The low halfword of a word; the cast keeps it.
    let half =
        |word: u32, high: bool| half_to_single((if high { word >> 16 } else { word }) as u16);
    V128(match kind {
        0 => {
            let byte = |shift: u32| ONE | ((w3 >> shift) & 0xFF);
            [byte(16), byte(8), byte(0), byte(24)]
        }
        1 => [short(w3, true), short(w3, false), 0, ONE],
        2 => [
            biased(w3, 10),
            biased(w3 >> 10, 10),
            biased(w3 >> 20, 10),
            ONE + (w3 >> 30),
        ],
        3 => [half(w3, true), half(w3, false), 0, ONE],
        4 => [
            short(w2, true),
            short(w2, false),
            short(w3, true),
            short(w3, false),
        ],
        5 => [
            half(w2, true),
            half(w2, false),
            half(w3, true),
            half(w3, false),
        ],
        _ => unsupported("vupkd3d128", kind),
    })
}

#[cold]
#[inline(never)]
fn unsupported(what: &str, kind: u8) -> ! {
    panic!("{what} {kind} is not supported; codegen never emits it")
}
