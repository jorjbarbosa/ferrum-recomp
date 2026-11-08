// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The vector instructions that move elements: permutes, selects, whole-register shifts,
//! merges, splats, packs and unpacks, the shift vectors of `lvsl` and `lvsr`, and the VMX128
//! permutes `vpermwi128` and `vrlimi128`.
//!
//! Elements are numbered from 0, the most significant.

use super::integer::{s16, s32, sat_i8, sat_i16, sat_u8, sat_u16, saturating};
use crate::{V128, Vscr};

/// The 32 bytes of `a` followed by those of `b`.
fn concat(a: V128, b: V128) -> [u8; 32] {
    let mut out = [0; 32];
    out[..16].copy_from_slice(&a.to_bytes());
    out[16..].copy_from_slice(&b.to_bytes());
    out
}

/// `vperm`: byte i is the byte of `a` and `b` (32 bytes) that the low 5 bits of byte i of `c`
/// index. `vperm128` takes `c` from v0 to v7.
#[inline]
pub fn vperm(a: V128, b: V128, c: V128) -> V128 {
    let source = concat(a, b);
    V128::from_bytes(c.to_bytes().map(|index| source[usize::from(index & 31)]))
}

/// `vsel`: the bits of `b` where `c` has a 1, those of `a` elsewhere. `vsel128 vD, vA, vB` is
/// `vsel(va, vb, vd)`.
#[inline]
pub fn vsel(a: V128, b: V128, c: V128) -> V128 {
    V128(std::array::from_fn(|i| {
        (a.0[i] & !c.0[i]) | (b.0[i] & c.0[i])
    }))
}

/// `vsldoi`: bytes `sh` to `sh` + 15 of `a` and `b`. `vsldoi128` is the same.
#[inline]
pub fn vsldoi(a: V128, b: V128, sh: u8) -> V128 {
    let source = concat(a, b);
    let sh = usize::from(sh & 15);
    V128::from_bytes(std::array::from_fn(|i| source[sh + i]))
}

/// `vsl`: `a` shifted left by bits 125:127 of `b`, the low 3 bits of byte 15. The ISA leaves the
/// result undefined unless every byte of `b` has the same low 3 bits.
#[inline]
pub fn vsl(a: V128, b: V128) -> V128 {
    V128::from_u128(a.to_u128() << (b.0[3] & 7))
}

/// `vsr`: `a` shifted right by bits 125:127 of `b`, filling with zeros (see [`vsl`]).
#[inline]
pub fn vsr(a: V128, b: V128) -> V128 {
    V128::from_u128(a.to_u128() >> (b.0[3] & 7))
}

/// `vslo`: `a` shifted left by the number of bytes in bits 121:124 of `b`. `vslo128` is the same.
#[inline]
pub fn vslo(a: V128, b: V128) -> V128 {
    V128::from_u128(a.to_u128() << (8 * ((b.0[3] >> 3) & 15)))
}

/// `vsro`: `a` shifted right by the number of bytes in bits 121:124 of `b`, filling with zeros.
#[inline]
pub fn vsro(a: V128, b: V128) -> V128 {
    V128::from_u128(a.to_u128() >> (8 * ((b.0[3] >> 3) & 15)))
}

/// Interleaves `N`-byte elements of `a` and `b`, starting at element `first` of each.
fn merge<const N: usize>(a: V128, b: V128, first: usize) -> V128 {
    let (a, b) = (a.to_bytes(), b.to_bytes());
    let mut out = [0; 16];
    for i in 0..8 / N {
        let at = (first + i) * N;
        out[2 * N * i..2 * N * i + N].copy_from_slice(&a[at..at + N]);
        out[2 * N * i + N..2 * N * (i + 1)].copy_from_slice(&b[at..at + N]);
    }
    V128::from_bytes(out)
}

/// `vmrghb`: bytes 0 to 7 of `a` and `b`, interleaved.
#[inline]
pub fn vmrghb(a: V128, b: V128) -> V128 {
    merge::<1>(a, b, 0)
}

/// `vmrglb`: bytes 8 to 15 of `a` and `b`, interleaved.
#[inline]
pub fn vmrglb(a: V128, b: V128) -> V128 {
    merge::<1>(a, b, 8)
}

/// `vmrghh`: halfwords 0 to 3 of `a` and `b`, interleaved.
#[inline]
pub fn vmrghh(a: V128, b: V128) -> V128 {
    merge::<2>(a, b, 0)
}

/// `vmrglh`: halfwords 4 to 7 of `a` and `b`, interleaved.
#[inline]
pub fn vmrglh(a: V128, b: V128) -> V128 {
    merge::<2>(a, b, 4)
}

/// `vmrghw`: words 0 and 1 of `a` and `b`, interleaved. `vmrghw128` is the same.
#[inline]
pub fn vmrghw(a: V128, b: V128) -> V128 {
    V128([a.0[0], b.0[0], a.0[1], b.0[1]])
}

/// `vmrglw`: words 2 and 3 of `a` and `b`, interleaved. `vmrglw128` is the same.
#[inline]
pub fn vmrglw(a: V128, b: V128) -> V128 {
    V128([a.0[2], b.0[2], a.0[3], b.0[3]])
}

/// `vspltb`: byte `uim` (modulo 16) of `b` in every byte.
#[inline]
pub fn vspltb(b: V128, uim: u8) -> V128 {
    V128::from_bytes([b.to_bytes()[usize::from(uim & 15)]; 16])
}

/// `vsplth`: halfword `uim` (modulo 8) of `b` in every halfword.
#[inline]
pub fn vsplth(b: V128, uim: u8) -> V128 {
    V128::from_halfwords([b.halfwords()[usize::from(uim & 7)]; 8])
}

/// `vspltw`: word `uim` (modulo 4) of `b` in every word. `vspltw128` is the same.
#[inline]
pub fn vspltw(b: V128, uim: u8) -> V128 {
    V128([b.0[usize::from(uim & 3)]; 4])
}

/// `vspltisb`: the signed immediate in every byte.
#[inline]
pub fn vspltisb(sim: i8) -> V128 {
    // The bits of the two's complement byte.
    V128::from_bytes([sim as u8; 16])
}

/// `vspltish`: the signed immediate in every halfword.
#[inline]
pub fn vspltish(sim: i8) -> V128 {
    // The bits of the sign-extended halfword.
    V128::from_halfwords([i16::from(sim) as u16; 8])
}

/// `vspltisw`: the signed immediate in every word. `vspltisw128` is the same.
#[inline]
pub fn vspltisw(sim: i8) -> V128 {
    // The bits of the sign-extended word.
    V128([i32::from(sim) as u32; 4])
}

/// `lvsl`: the shift vector for EA: byte i is `sh + i`, with `sh` the low 4 bits of `ea`.
#[inline]
pub fn lvsl(ea: u32) -> V128 {
    // The mask keeps 4 bits, so the cast loses nothing.
    let sh = (ea & 15) as u8;
    V128::from_bytes(std::array::from_fn(|i| sh + i as u8))
}

/// `lvsr`: the shift vector for EA: byte i is `16 - sh + i`.
#[inline]
pub fn lvsr(ea: u32) -> V128 {
    // The mask keeps 4 bits, so the cast loses nothing.
    let sh = (ea & 15) as u8;
    V128::from_bytes(std::array::from_fn(|i| 16 - sh + i as u8))
}

/// Packs the eight halfwords of `a` and `b` into bytes with `pack`.
fn pack_halfwords(a: V128, b: V128, mut pack: impl FnMut(u16) -> u8) -> V128 {
    let (a, b) = (a.halfwords(), b.halfwords());
    V128::from_bytes(std::array::from_fn(|i| {
        pack(if i < 8 { a[i] } else { b[i - 8] })
    }))
}

/// Packs the four words of `a` and `b` into halfwords with `pack`.
fn pack_words(a: V128, b: V128, mut pack: impl FnMut(u32) -> u16) -> V128 {
    V128::from_halfwords(std::array::from_fn(|i| {
        pack(if i < 4 { a.0[i] } else { b.0[i - 4] })
    }))
}

/// `vpkuhum`: the low bytes of the halfwords of `a`, then of `b`.
#[inline]
pub fn vpkuhum(a: V128, b: V128) -> V128 {
    // The low byte is the modulo.
    pack_halfwords(a, b, |x| x as u8)
}

/// `vpkuwum`: the low halfwords of the words of `a`, then of `b`.
#[inline]
pub fn vpkuwum(a: V128, b: V128) -> V128 {
    // The low halfword is the modulo.
    pack_words(a, b, |x| x as u16)
}

/// `vpkuhus`: the unsigned halfwords of `a` and `b` as unsigned bytes, saturated.
#[inline]
pub fn vpkuhus(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    saturating(vscr, |sat| {
        pack_halfwords(a, b, |x| sat_u8(i64::from(x), sat))
    })
}

/// `vpkshus`: the signed halfwords of `a` and `b` as unsigned bytes, saturated.
#[inline]
pub fn vpkshus(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    saturating(vscr, |sat| pack_halfwords(a, b, |x| sat_u8(s16(x), sat)))
}

/// `vpkshss`: the signed halfwords of `a` and `b` as signed bytes, saturated.
#[inline]
pub fn vpkshss(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    saturating(vscr, |sat| pack_halfwords(a, b, |x| sat_i8(s16(x), sat)))
}

/// `vpkuwus`: the unsigned words of `a` and `b` as unsigned halfwords, saturated.
#[inline]
pub fn vpkuwus(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    saturating(vscr, |sat| pack_words(a, b, |x| sat_u16(i64::from(x), sat)))
}

/// `vpkswus`: the signed words of `a` and `b` as unsigned halfwords, saturated.
#[inline]
pub fn vpkswus(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    saturating(vscr, |sat| pack_words(a, b, |x| sat_u16(s32(x), sat)))
}

/// `vpkswss`: the signed words of `a` and `b` as signed halfwords, saturated.
#[inline]
pub fn vpkswss(vscr: &mut Vscr, a: V128, b: V128) -> V128 {
    saturating(vscr, |sat| pack_words(a, b, |x| sat_i16(s32(x), sat)))
}

/// `vpkpx`: each word of `a` and `b`, a 32-bit pixel, as a 1/5/5/5 pixel: bit 7, bits 8:12,
/// bits 16:20 and bits 24:28.
#[inline]
pub fn vpkpx(a: V128, b: V128) -> V128 {
    pack_words(a, b, |w| {
        let pixel = ((w >> 24) & 1) << 15
            | ((w >> 19) & 0x1F) << 10
            | ((w >> 11) & 0x1F) << 5
            | ((w >> 3) & 0x1F);
        // Sixteen bits were assembled.
        pixel as u16
    })
}

/// `vupkhsb`: bytes 0 to 7 of `b`, sign-extended to halfwords.
#[inline]
pub fn vupkhsb(b: V128) -> V128 {
    let bytes = b.to_bytes();
    // Sign extension of each byte, kept as bits.
    V128::from_halfwords(std::array::from_fn(|i| i16::from(bytes[i] as i8) as u16))
}

/// `vupklsb`: bytes 8 to 15 of `b`, sign-extended to halfwords.
#[inline]
pub fn vupklsb(b: V128) -> V128 {
    let bytes = b.to_bytes();
    // Sign extension of each byte, kept as bits.
    V128::from_halfwords(std::array::from_fn(|i| {
        i16::from(bytes[i + 8] as i8) as u16
    }))
}

/// `vupkhsh`: halfwords 0 to 3 of `b`, sign-extended to words.
#[inline]
pub fn vupkhsh(b: V128) -> V128 {
    let halfwords = b.halfwords();
    // Sign extension of each halfword, kept as bits.
    V128(std::array::from_fn(|i| s16(halfwords[i]) as u32))
}

/// `vupklsh`: halfwords 4 to 7 of `b`, sign-extended to words.
#[inline]
pub fn vupklsh(b: V128) -> V128 {
    let halfwords = b.halfwords();
    // Sign extension of each halfword, kept as bits.
    V128(std::array::from_fn(|i| s16(halfwords[i + 4]) as u32))
}

/// A 1/5/5/5 pixel as a 32-bit one: the first bit extended to a byte, each field zero-extended.
fn unpack_pixel(h: u16) -> u32 {
    let h = u32::from(h);
    let alpha = if h & 0x8000 != 0 { 0xFF00_0000 } else { 0 };
    alpha | ((h >> 10) & 0x1F) << 16 | ((h >> 5) & 0x1F) << 8 | (h & 0x1F)
}

/// `vupkhpx`: halfwords 0 to 3 of `b`, 1/5/5/5 pixels, as 8/8/8/8 pixels.
#[inline]
pub fn vupkhpx(b: V128) -> V128 {
    let halfwords = b.halfwords();
    V128(std::array::from_fn(|i| unpack_pixel(halfwords[i])))
}

/// `vupklpx`: halfwords 4 to 7 of `b` as 8/8/8/8 pixels.
#[inline]
pub fn vupklpx(b: V128) -> V128 {
    let halfwords = b.halfwords();
    V128(std::array::from_fn(|i| unpack_pixel(halfwords[i + 4])))
}

/// `vpermwi128`: word i is word `(perm >> (6 - 2i)) & 3` of `b`.
#[inline]
pub fn vpermwi128(b: V128, perm: u8) -> V128 {
    V128(std::array::from_fn(|i| {
        b.0[usize::from((perm >> (6 - 2 * i)) & 3)]
    }))
}

/// `vrlimi128`: `b` rotated left by `rot` words, taken in word i where bit `3 - i` of `mask` is
/// set; `d` keeps the other words.
#[inline]
pub fn vrlimi128(d: V128, b: V128, mask: u8, rot: u8) -> V128 {
    let rot = usize::from(rot & 3);
    V128(std::array::from_fn(|i| {
        if mask & (8 >> i) != 0 {
            b.0[(i + rot) % 4]
        } else {
            d.0[i]
        }
    }))
}
