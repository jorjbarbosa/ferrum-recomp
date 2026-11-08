// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::{counting, splat, v, vscr};
use crate::V128;
use crate::ops::*;

#[test]
fn vperm_indexes_with_the_low_five_bits() {
    let (a, b) = (counting(0x00), counting(0x10));
    assert_eq!(vperm(a, b, splat(0x0101_0101)), splat(0x0101_0101));
    assert_eq!(vperm(a, b, splat(0x1111_1111)), splat(0x1111_1111));
    // 0x21 indexes byte 1: the high bits are ignored (test_vperm_4).
    assert_eq!(vperm(a, b, splat(0x2121_2121)), splat(0x0101_0101));
    assert_eq!(vperm(a, b, splat(0xFFE0_9F1F)), splat(0x1F00_1F1F));
    let c = v(0x0102_0003, 0x1415_0001, 0x1F1C_1D1E, 0x0014_1518);
    assert_eq!(vperm(a, b, c), c, "test_vperm_5");
}

#[test]
fn vsel_takes_b_where_c_is_one() {
    let (a, b) = (counting(0x00), counting(0x10));
    assert_eq!(vsel(a, b, V128::ZERO), a);
    assert_eq!(vsel(a, b, splat(u32::MAX)), b);
    assert_eq!(
        vsel(splat(0), splat(u32::MAX), splat(0x0123_4567)),
        splat(0x0123_4567)
    );
    assert_eq!(
        vsel(splat(0x0C01_0203), splat(0x1D11_1213), splat(0x1010_1010)),
        splat(0x1C11_1213)
    );
}

#[test]
fn vsldoi_takes_sixteen_bytes_from_the_concatenation() {
    let (a, b) = (counting(0x00), counting(0x10));
    assert_eq!(vsldoi(a, b, 0), a);
    assert_eq!(vsldoi(a, b, 4), counting(0x04));
    assert_eq!(vsldoi(a, b, 15), counting(0x0F));
}

#[test]
fn whole_register_shifts_use_byte_15() {
    let x = v(0x0011_2233, 0x4455_6677, 0x8899_AABB, 0xCCDD_EEFF);
    assert_eq!(
        vsl(x, splat(0x0404_0404)),
        v(0x0112_2334, 0x4556_6778, 0x899A_ABBC, 0xCDDE_EFF0)
    );
    assert_eq!(
        vsr(x, splat(0x0404_0404)),
        v(0x0001_1223, 0x3445_5667, 0x7889_9AAB, 0xBCCD_DEEF)
    );
    // Only the low three bits count, and only those of byte 15.
    assert_eq!(vsl(x, splat(0xFFFF_FFFF)), vsl(x, splat(0x0707_0707)));
    assert_eq!(
        vsl(x, v(0, 0, 0, 0x0000_0001)),
        V128::from_u128(x.to_u128() << 1)
    );
    // By bytes: bits 121:124, so 0x80 shifts by 0 and 0xFF by 15.
    assert_eq!(
        vslo(x, splat(0x0808_0808)),
        v(0x1122_3344, 0x5566_7788, 0x99AA_BBCC, 0xDDEE_FF00)
    );
    assert_eq!(vslo(x, splat(0x8080_8080)), x);
    assert_eq!(vslo(x, splat(u32::MAX)), v(0xFF00_0000, 0, 0, 0));
    assert_eq!(
        vsro(x, splat(0x1212_1212)),
        v(0x0000_0011, 0x2233_4455, 0x6677_8899, 0xAABB_CCDD)
    );
    assert_eq!(vsro(x, splat(u32::MAX)), V128::ZERO);
}

#[test]
fn merges_interleave_high_or_low_halves() {
    let (a, b) = (counting(0x00), counting(0x10));
    assert_eq!(
        vmrghb(a, b),
        v(0x0010_0111, 0x0212_0313, 0x0414_0515, 0x0616_0717)
    );
    assert_eq!(
        vmrglb(a, b),
        v(0x0818_0919, 0x0A1A_0B1B, 0x0C1C_0D1D, 0x0E1E_0F1F)
    );
    assert_eq!(
        vmrghh(a, b),
        v(0x0001_1011, 0x0203_1213, 0x0405_1415, 0x0607_1617)
    );
    assert_eq!(
        vmrglh(a, b),
        v(0x0809_1819, 0x0A0B_1A1B, 0x0C0D_1C1D, 0x0E0F_1E1F)
    );
    assert_eq!(
        vmrghw(a, b),
        v(0x0001_0203, 0x1011_1213, 0x0405_0607, 0x1415_1617)
    );
    assert_eq!(
        vmrglw(a, b),
        v(0x0809_0A0B, 0x1819_1A1B, 0x0C0D_0E0F, 0x1C1D_1E1F)
    );
}

#[test]
fn splats_copy_one_element_or_an_immediate() {
    let x = counting(0x00);
    assert_eq!(vspltb(x, 3), splat(0x0303_0303));
    assert_eq!(vspltb(x, 15), splat(0x0F0F_0F0F));
    assert_eq!(vsplth(x, 7), splat(0x0E0F_0E0F));
    assert_eq!(vspltw(x, 2), splat(0x0809_0A0B));
    assert_eq!(vspltisb(-16), splat(0xF0F0_F0F0));
    assert_eq!(vspltish(-1), splat(u32::MAX));
    assert_eq!(vspltish(15), splat(0x000F_000F));
    assert_eq!(vspltisw(-16), splat(0xFFFF_FFF0));
    assert_eq!(vspltisw(15), splat(15));
}

#[test]
fn shift_vectors_depend_on_the_low_four_bits() {
    assert_eq!(lvsl(0x1070), counting(0x00));
    assert_eq!(lvsl(0x1071), counting(0x01));
    assert_eq!(lvsl(0xFFFF_FFFF), counting(0x0F));
    assert_eq!(lvsr(0x1070), counting(0x10));
    assert_eq!(lvsr(0x1071), counting(0x0F));
    assert_eq!(lvsr(0x107F), counting(0x01));
}

#[test]
fn packs_wrap_or_saturate() {
    let a = v(0x7FFF_8000, 0x0005_FFFF, 0x0100_00FF, 0x0080_FF80);
    let b = v(0x0001_0002, 0x0003_0004, 0x0005_0006, 0x0007_0008);
    assert_eq!(
        vpkuhum(a, b),
        v(0xFF00_05FF, 0x00FF_8080, 0x0102_0304, 0x0506_0708)
    );
    let mut s = vscr(true);
    assert_eq!(
        vpkshss(&mut s, a, b),
        v(0x7F80_05FF, 0x7F7F_7F80, 0x0102_0304, 0x0506_0708)
    );
    assert!(s.sat());
    let mut s = vscr(true);
    assert_eq!(
        vpkshus(&mut s, a, b),
        v(0xFF00_0500, 0xFFFF_8000, 0x0102_0304, 0x0506_0708)
    );
    assert!(s.sat());
    let mut s = vscr(true);
    assert_eq!(
        vpkuhus(&mut s, a, b),
        v(0xFFFF_05FF, 0xFFFF_80FF, 0x0102_0304, 0x0506_0708)
    );
    assert!(s.sat());
    let mut s = vscr(true);
    assert_eq!(
        vpkuhus(&mut s, b, b),
        v(0x0102_0304, 0x0506_0708, 0x0102_0304, 0x0506_0708)
    );
    assert!(!s.sat());
    let a = v(0x0001_8000, 0xFFFF_FFFF, 0x7FFF_FFFF, 5);
    let b = v(0x8000_0000, 0x0000_7FFF, 0x0000_8000, 0x0001_0000);
    assert_eq!(
        vpkuwum(a, b),
        v(0x8000_FFFF, 0xFFFF_0005, 0x0000_7FFF, 0x8000_0000)
    );
    let mut s = vscr(true);
    assert_eq!(
        vpkswss(&mut s, a, b),
        v(0x7FFF_FFFF, 0x7FFF_0005, 0x8000_7FFF, 0x7FFF_7FFF)
    );
    assert!(s.sat());
    let mut s = vscr(true);
    assert_eq!(
        vpkswus(&mut s, a, b),
        v(0xFFFF_0000, 0xFFFF_0005, 0x0000_7FFF, 0x8000_FFFF)
    );
    assert!(s.sat());
    let mut s = vscr(true);
    assert_eq!(
        vpkuwus(&mut s, a, b),
        v(0xFFFF_FFFF, 0xFFFF_0005, 0xFFFF_7FFF, 0x8000_FFFF)
    );
    assert!(s.sat());
}

#[test]
fn pixels_pack_and_unpack() {
    // 0x01FF7F3F: bit 7 set, then the top five bits of 0xFF, 0x7F and 0x3F: 1 11111 01111 00111.
    let a = v(0x01FF_7F3F, 0, 0xFE00_0000, 0x00F8_F8F8);
    let r = vpkpx(a, V128::ZERO);
    assert_eq!(r, v(0xFDE7_0000, 0x0000_7FFF, 0, 0));
    assert_eq!(vupkhpx(r), v(0xFF1F_0F07, 0, 0, 0x001F_1F1F));
    assert_eq!(
        vupklpx(v(0, 0, 0x8000_0001, 0x7C00_03E0)),
        v(0xFF00_0000, 0x0000_0001, 0x001F_0000, 0x0000_1F00)
    );
}

#[test]
fn unpacks_sign_extend() {
    let x = v(0x807F_01FF, 0x0000_0000, 0x8000_7FFF, 0xFFFF_0001);
    assert_eq!(vupkhsb(x), v(0xFF80_007F, 0x0001_FFFF, 0, 0));
    assert_eq!(
        vupklsb(x),
        v(0xFF80_0000, 0x007F_FFFF, 0xFFFF_FFFF, 0x0000_0001)
    );
    assert_eq!(vupkhsh(x), v(0xFFFF_807F, 0x0000_01FF, 0, 0));
    assert_eq!(vupklsh(x), v(0xFFFF_8000, 0x0000_7FFF, 0xFFFF_FFFF, 1));
}

#[test]
fn vpermwi128_selects_words_two_bits_each() {
    let x = counting(0x00);
    assert_eq!(vpermwi128(x, 0x1B), x, "0, 1, 2, 3");
    assert_eq!(
        vpermwi128(x, 0xE4),
        v(0x0C0D_0E0F, 0x0809_0A0B, 0x0405_0607, 0x0001_0203)
    );
    assert_eq!(vpermwi128(x, 0x00), splat(0x0001_0203));
    assert_eq!(vpermwi128(x, 0xFF), splat(0x0C0D_0E0F));
}

#[test]
fn vrlimi128_rotates_words_and_inserts_by_mask() {
    let (d, b) = (splat(0xCCCC_CCCC), counting(0x00));
    assert_eq!(vrlimi128(d, b, 0, 0), d);
    assert_eq!(vrlimi128(d, b, 0xF, 0), b);
    assert_eq!(
        vrlimi128(d, b, 0xF, 1),
        v(0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F, 0x0001_0203)
    );
    assert_eq!(
        vrlimi128(d, b, 0xF, 3),
        v(0x0C0D_0E0F, 0x0001_0203, 0x0405_0607, 0x0809_0A0B)
    );
    assert_eq!(
        vrlimi128(d, b, 0x8, 0),
        v(0x0001_0203, 0xCCCC_CCCC, 0xCCCC_CCCC, 0xCCCC_CCCC)
    );
    assert_eq!(
        vrlimi128(d, b, 0x1, 0),
        v(0xCCCC_CCCC, 0xCCCC_CCCC, 0xCCCC_CCCC, 0x0C0D_0E0F)
    );
    assert_eq!(
        vrlimi128(d, b, 0x6, 2),
        v(0xCCCC_CCCC, 0x0C0D_0E0F, 0x0001_0203, 0xCCCC_CCCC)
    );
}
