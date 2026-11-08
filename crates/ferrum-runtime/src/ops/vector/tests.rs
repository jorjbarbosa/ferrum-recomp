// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Unit tests of the vector helpers. Expected values come from the definitions in Book I,
//! chapter 6, of the Power ISA v3.1C, or for VMX128, which no ISA book defines, from the sources
//! the docs of its helpers cite. The non-obvious ones were worked out with exact rational
//! arithmetic in Python (`fractions`, and `decimal` at 60 digits for 2^x and log2), independently
//! of this code.

mod d3d;
mod float;
mod integer;
mod memory;
mod permute;

use crate::{V128, Vscr};

/// A vector from its four words.
fn v(w0: u32, w1: u32, w2: u32, w3: u32) -> V128 {
    V128([w0, w1, w2, w3])
}

/// The same word in all four lanes.
fn splat(w: u32) -> V128 {
    V128([w; 4])
}

/// A VSCR in non-Java mode (NJ set) or Java mode, SAT clear.
fn vscr(nj: bool) -> Vscr {
    Vscr::from_u32(if nj { Vscr::NJ } else { 0 })
}

/// The 16 bytes `start`, `start + 1`, ... as a vector.
fn counting(start: u8) -> V128 {
    V128::from_bytes(std::array::from_fn(|i| start + i as u8))
}
