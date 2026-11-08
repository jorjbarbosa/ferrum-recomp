// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::{counting, v};
use crate::V128;
use crate::ops::*;
use crate::test_support::{block, memory};

/// A fresh block with bytes 0x40, 0x41, ... from its start, and the address of its second
/// quadword.
fn filled() -> u32 {
    let base = block();
    let bytes: Vec<u8> = (0..64u8).map(|i| 0x40 + i).collect();
    memory().write_bytes(base, &bytes);
    base + 16
}

#[test]
fn lvlx_loads_from_ea_to_the_end_of_its_quadword() {
    let mem = memory();
    let at = filled();
    assert_eq!(lvlx(mem, at), counting(0x50), "aligned: the whole quadword");
    assert_eq!(
        lvlx(mem, at + 7),
        v(0x5758_595A, 0x5B5C_5D5E, 0x5F00_0000, 0)
    );
    assert_eq!(lvlx(mem, at + 15), v(0x5F00_0000, 0, 0, 0));
}

#[test]
fn lvrx_loads_from_the_start_of_the_quadword_up_to_ea() {
    let mem = memory();
    let at = filled();
    assert_eq!(lvrx(mem, at), V128::ZERO, "aligned: nothing");
    assert_eq!(lvrx(mem, at + 7), v(0, 0, 0x0050_5152, 0x5354_5556));
    assert_eq!(
        lvrx(mem, at + 15),
        v(0x0050_5152, 0x5354_5556, 0x5758_595A, 0x5B5C_5D5E)
    );
    // lvlx and lvrx of the next quadword together read 16 unaligned bytes.
    let pair = lvlx(mem, at + 7).to_u128() | lvrx(mem, at + 7 + 16).to_u128();
    assert_eq!(V128::from_u128(pair), counting(0x57));
}

/// With the `trace` feature every access outside a registered region panics, so an aligned
/// `lvrx` or `stvrx` outside every region shows that they touch nothing.
#[cfg(feature = "trace")]
#[test]
fn aligned_lvrx_and_stvrx_touch_no_memory() {
    let mem = memory();
    assert_eq!(lvrx(mem, 0x1000_0000), V128::ZERO);
    stvrx(mem, 0x1000_0000, counting(1));
}

#[test]
fn stvlx_and_stvrx_store_only_their_bytes() {
    let mem = memory();
    let at = filled();
    let x = counting(0xA0);
    stvlx(mem, at + 4, x);
    stvrx(mem, at + 16 + 4, x);
    stvrx(mem, at + 32, x);
    let mut bytes = [0; 48];
    mem.read_bytes(at - 16, &mut bytes);
    let expected: Vec<u8> = (0..48u8)
        .map(|i| match i {
            // stvlx at offset 4 of the second quadword: x bytes 0 to 11 at offsets 4 to 15.
            20..=31 => 0xA0 + (i - 20),
            // stvrx at offset 4 of the third quadword: x bytes 12 to 15 at offsets 0 to 3.
            32..=35 => 0xAC + (i - 32),
            _ => 0x40 + i,
        })
        .collect();
    assert_eq!(bytes.as_slice(), expected.as_slice());
    // The aligned stvrx stored nothing: the fourth quadword is untouched.
    assert_eq!(mem.read_u8(at + 32), 0x70);
}

#[test]
fn element_stores_write_one_aligned_element() {
    let mem = memory();
    let at = filled();
    let x = v(0x0001_0203, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F);
    stvebx(mem, at + 5, x);
    // An odd address stores the halfword at the even one below it, element 3.
    stvehx(mem, at + 7, x);
    // Offset 11 stores word element 2 at offset 8.
    stvewx(mem, at + 11, x);
    let mut bytes = [0; 16];
    mem.read_bytes(at, &mut bytes);
    assert_eq!(
        bytes,
        [
            0x50, 0x51, 0x52, 0x53, 0x54, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x5C, 0x5D,
            0x5E, 0x5F
        ]
    );
}
