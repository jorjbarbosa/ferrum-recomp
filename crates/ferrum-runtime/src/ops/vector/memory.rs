// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The vector loads and stores that move part of a quadword: the element stores and the Xenon's
//! `lvlx`, `lvrx`, `stvlx` and `stvrx`, with their `l` and VMX128 forms.
//!
//! Each touches only the bytes it moves, so an `lvrx` or `stvrx` at an aligned address reads or
//! writes nothing. The aligned loads and stores (`lvx`, `stvx` and the element loads) are a
//! [`Memory::read_v128`] or [`Memory::write_v128`] at the address with its low 4 bits cleared,
//! which generated code does itself.

use crate::{Memory, V128};

/// The offset of `ea` in its aligned quadword.
fn offset(ea: u32) -> usize {
    // The mask keeps 4 bits.
    (ea & 15) as usize
}

/// `lvlx`: the bytes from `ea` to the end of its aligned quadword, in bytes 0 up; zeros after.
#[cfg_attr(feature = "trace", track_caller)]
pub fn lvlx(mem: &Memory, ea: u32) -> V128 {
    let sh = offset(ea);
    let mut bytes = [0; 16];
    mem.read_bytes(ea, &mut bytes[..16 - sh]);
    V128::from_bytes(bytes)
}

/// `lvrx`: the bytes from the start of the aligned quadword of `ea` up to `ea`, in the last bytes;
/// zeros before. An aligned `ea` gives zero without reading memory.
#[cfg_attr(feature = "trace", track_caller)]
pub fn lvrx(mem: &Memory, ea: u32) -> V128 {
    let sh = offset(ea);
    let mut bytes = [0; 16];
    mem.read_bytes(ea & !15, &mut bytes[16 - sh..]);
    V128::from_bytes(bytes)
}

/// `stvlx`: the first `16 - (ea & 15)` bytes of `v`, from `ea` to the end of its quadword.
#[cfg_attr(feature = "trace", track_caller)]
pub fn stvlx(mem: &Memory, ea: u32, v: V128) {
    let sh = offset(ea);
    mem.write_bytes(ea, &v.to_bytes()[..16 - sh]);
}

/// `stvrx`: the last `ea & 15` bytes of `v`, from the start of the quadword of `ea` up to `ea`.
/// An aligned `ea` stores nothing.
#[cfg_attr(feature = "trace", track_caller)]
pub fn stvrx(mem: &Memory, ea: u32, v: V128) {
    let sh = offset(ea);
    mem.write_bytes(ea & !15, &v.to_bytes()[16 - sh..]);
}

/// `stvebx`: byte element `ea & 15` of `v`, at `ea`.
#[cfg_attr(feature = "trace", track_caller)]
pub fn stvebx(mem: &Memory, ea: u32, v: V128) {
    mem.write_u8(ea, v.to_bytes()[offset(ea)]);
}

/// `stvehx`: halfword element `(ea & 15) >> 1` of `v`, at `ea` with its low bit cleared.
#[cfg_attr(feature = "trace", track_caller)]
pub fn stvehx(mem: &Memory, ea: u32, v: V128) {
    mem.write_u16(ea & !1, v.halfwords()[offset(ea) >> 1]);
}

/// `stvewx`: word element `(ea & 15) >> 2` of `v`, at `ea` with its low 2 bits cleared.
/// `stvewx128` is the same.
#[cfg_attr(feature = "trace", track_caller)]
pub fn stvewx(mem: &Memory, ea: u32, v: V128) {
    mem.write_u32(ea & !3, v.0[offset(ea) >> 2]);
}
