// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::{splat, v};
use crate::ops::vector::d3d::{half_to_single, single_to_half};
use crate::ops::*;

const CD: u32 = 0xCDCD_CDCD;

#[test]
fn d3dcolor_packs_biased_bytes_and_places_them_by_mask_and_shift() {
    let d = splat(CD);
    let x = v(0x4040_0001, 0x4040_0002, 0x4040_0003, 0x4040_0004);
    // W, X, Y, Z from bits 24, 16, 8 and 0.
    let packed = 0x0401_0203;
    for (shift, expected) in [
        (0, v(CD, CD, CD, packed)),
        (1, v(CD, CD, packed, CD)),
        (2, v(CD, packed, CD, CD)),
        (3, v(packed, CD, CD, CD)),
    ] {
        assert_eq!(
            vpkd3d128(d, x, 0, 1, shift),
            expected,
            "mask 1, shift {shift}"
        );
    }
    // Masks 2 and 3 place two words, the first zero for a one-word format.
    for (mask, shift, expected) in [
        (2, 0, v(CD, CD, 0, packed)),
        (2, 1, v(CD, 0, packed, CD)),
        (2, 2, v(0, packed, CD, CD)),
        (2, 3, v(packed, CD, CD, CD)),
        (3, 2, v(0, packed, CD, CD)),
        (3, 3, v(CD, CD, CD, 0)),
    ] {
        assert_eq!(
            vpkd3d128(d, x, 0, mask, shift),
            expected,
            "mask {mask}, shift {shift}"
        );
    }
}

#[test]
fn packs_clamp_with_nans_at_the_low_bound() {
    let d = splat(CD);
    // Tiny denormals are below 3.0; 4.0 and a large number are above 3.0 + 255 × 2^-22; 2.0,
    // -123 and the NaN 0xFFFFFFFF are below.
    assert_eq!(vpkd3d128(d, v(1, 2, 3, 4), 0, 1, 0).0[3], 0);
    assert_eq!(
        vpkd3d128(
            d,
            v(0x4080_0000, 0x4000_0000, 0xC2F6_0000, 0x4B3B_DF83),
            0,
            1,
            0
        )
        .0[3],
        0xFFFF_0000
    );
    assert_eq!(
        vpkd3d128(
            d,
            v(0x4080_0000, 0x4000_0000, 0xC2F6_0000, u32::MAX),
            0,
            1,
            0
        )
        .0[3],
        0x00FF_0000
    );
    // SHORT_2: 3.0 ± 32767 × 2^-22.
    assert_eq!(
        vpkd3d128(d, v(0x4381_7E00, 0xC37C_FC00, 0, 0), 1, 1, 0).0[3],
        0x7FFF_8001
    );
    assert_eq!(
        vpkd3d128(d, v(0x4040_4000, 0x403F_C000, 0, 0), 1, 1, 0).0[3],
        0x4000_C000
    );
    assert_eq!(
        vpkd3d128(d, v(0x7FC0_0000, 0x4040_FFFE, 0, 0), 1, 1, 0).0[3],
        0x8001_7FFF
    );
    // SHORT_4 fills two words.
    assert_eq!(
        vpkd3d128(
            d,
            v(0x403F_8001, 0x403F_FFF8, 0x4040_007F, 0x4040_0000),
            4,
            2,
            0
        ),
        v(CD, CD, 0x8001_FFF8, 0x007F_0000)
    );
}

#[test]
fn packs_2_10_10_10_signed_xyz_and_unsigned_w() {
    let d = splat(CD);
    // X, Y and Z clamp to -511 (0x201) and W to 3: 11 1000000001 1000000001 1000000001.
    let x = v(0xB8FF_8000, 0xB8FF_8000, 0xC040_01FF, 0x4E9A_5A5A);
    assert_eq!(vpkd3d128(d, x, 2, 1, 0).0[3], 0xE018_0601);
    // 100 clamps to 511, -100 to -511, 3.0 is 0 and 1.0 clamps W to 0.
    let x = v(0x42C8_0000, 0xC2C8_0000, 0x4040_0000, 0x3F80_0000);
    assert_eq!(vpkd3d128(d, x, 2, 1, 0).0[3], 0x0008_05FF);
}

#[test]
fn half_packs_round_toward_zero() {
    let d = splat(CD);
    let x = v(0x3FC0_0000, 0xBFC0_0000, 0x3F00_0000, 0xBF80_0000);
    assert_eq!(vpkd3d128(d, x, 3, 1, 0).0[3], 0x3E00_BE00, "1.5 and -1.5");
    assert_eq!(
        vpkd3d128(d, x, 5, 2, 0),
        v(CD, CD, 0x3E00_BE00, 0x3800_BC00)
    );
    for (single, half) in [
        (0x3F80_0000, 0x3C00), // 1
        (0x3F80_2000, 0x3C01), // 1 + 2^-10
        (0x3F80_1000, 0x3C00), // 1 + 2^-11 truncates
        (0x477F_E000, 0x7BFF), // 65504, the largest half
        (0x4780_0000, 0x7BFF), // 65536 is above it
        (0x7F80_0000, 0x7C00),
        (0xFF80_0000, 0xFC00),
        (0x7FC0_0000, 0x7E00),
        (0x7F80_0001, 0x7E00), // signaling, quieted
        (0xFFC0_2000, 0xFE01), // the top 10 bits of the payload stay
        (0x3380_0000, 0x0001), // 2^-24, the smallest half
        (0x33C0_0000, 0x0001), // 1.5 × 2^-24 truncates
        (0x3300_0000, 0x0000), // 2^-25
        (0x3880_0000, 0x0400), // 2^-14, the smallest normal half
        (0x8000_0000, 0x8000),
        (0x0000_0001, 0x0000), // a single denormal
    ] {
        assert_eq!(single_to_half(single), half, "{single:#010x}");
    }
}

#[test]
fn halves_widen_exactly() {
    for (half, single) in [
        (0x3C00, 0x3F80_0000),
        (0xB801, 0xBF00_2000),
        (0x0001, 0x3380_0000),
        (0x03FF, 0x387F_C000),
        (0x0200, 0x3800_0000),
        (0x7C00, 0x7F80_0000),
        (0x7E01, 0x7FC0_2000),
        (0x8000, 0x8000_0000),
    ] {
        assert_eq!(half_to_single(half), single, "{half:#06x}");
    }
}

#[test]
fn unpacks_reverse_the_packs() {
    // D3DCOLOR: X, Y, Z, W from bits 16, 8, 0 and 24 of word 3, as 1.0 + n × 2^-23.
    assert_eq!(
        vupkd3d128(v(CD, CD, CD, 0x0401_0203), 0),
        v(0x3F80_0001, 0x3F80_0002, 0x3F80_0003, 0x3F80_0004)
    );
    // SHORT_2: -32768 gives the NaN.
    assert_eq!(
        vupkd3d128(v(CD, CD, CD, 0x7FFF_8001), 1),
        v(0x4040_7FFF, 0x403F_8001, 0, 0x3F80_0000)
    );
    assert_eq!(
        vupkd3d128(v(CD, CD, CD, 0x0000_8000), 1),
        v(0x4040_0000, 0x7FC0_0000, 0, 0x3F80_0000)
    );
    assert_eq!(
        vupkd3d128(v(CD, CD, 0x7FFF_FFFF, 0x007F_FFF8), 4),
        v(0x4040_7FFF, 0x403F_FFFF, 0x4040_007F, 0x403F_FFF8)
    );
    // 2_10_10_10: X = 511, Y = Z = 0, W = 1; then X = -511; then X = -512, the NaN.
    assert_eq!(
        vupkd3d128(v(CD, CD, CD, 0x4000_01FF), 2),
        v(0x4040_01FF, 0x4040_0000, 0x4040_0000, 0x3F80_0001)
    );
    assert_eq!(vupkd3d128(v(CD, CD, CD, 0x4000_0201), 2).0[0], 0x403F_FE01);
    assert_eq!(vupkd3d128(v(CD, CD, CD, 0x4000_0200), 2).0[0], 0x7FC0_0000);
    assert_eq!(
        vupkd3d128(v(CD, CD, CD, 0x3800_B800), 3),
        v(0x3F00_0000, 0xBF00_0000, 0, 0x3F80_0000)
    );
    assert_eq!(
        vupkd3d128(v(CD, CD, 0x3800_B801, 0x3802_B803), 5),
        v(0x3F00_0000, 0xBF00_2000, 0x3F00_4000, 0xBF00_6000)
    );
}

#[test]
#[should_panic(expected = "codegen never emits it")]
fn the_kinds_codegen_rejects_panic() {
    vpkd3d128(splat(0), splat(0), 6, 1, 0);
}
