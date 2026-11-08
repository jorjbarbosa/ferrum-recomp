// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The VMX and VMX128 instructions, one helper per instruction, working on [`V128`] lane by lane.
//!
//! The helpers are named after the instructions. A VMX128 form that only widens the register
//! fields uses the VMX helper (`vaddfp128` is [`vaddfp`]); those whose meaning differs have their
//! own (`vmulfp128`, `vpermwi128`, `vrlimi128`, `vpkd3d128`, ...).

pub(crate) mod d3d;
mod float;
mod integer;
mod memory;
mod permute;

#[cfg(test)]
mod tests;

pub use d3d::{vpkd3d128, vupkd3d128};
pub use float::*;
pub use integer::*;
pub use memory::*;
pub use permute::*;

use crate::V128;

/// Applies `op` to each pair of byte elements of `a` and `b`.
fn bytes(a: V128, b: V128, mut op: impl FnMut(u8, u8) -> u8) -> V128 {
    let (a, b) = (a.to_bytes(), b.to_bytes());
    V128::from_bytes(std::array::from_fn(|i| op(a[i], b[i])))
}

/// Applies `op` to each pair of halfword elements of `a` and `b`.
fn halfwords(a: V128, b: V128, mut op: impl FnMut(u16, u16) -> u16) -> V128 {
    let (a, b) = (a.halfwords(), b.halfwords());
    V128::from_halfwords(std::array::from_fn(|i| op(a[i], b[i])))
}

/// Applies `op` to each pair of word elements of `a` and `b`.
fn words(a: V128, b: V128, mut op: impl FnMut(u32, u32) -> u32) -> V128 {
    V128(std::array::from_fn(|i| op(a.0[i], b.0[i])))
}
