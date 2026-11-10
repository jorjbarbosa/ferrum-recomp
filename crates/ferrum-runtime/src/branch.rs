// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! What generated code calls when a branch inside a function reaches an address where none of the
//! function's blocks starts.

#[cfg(test)]
mod tests;

/// Panics because the generated function `function` was sent to `target`, where none of its
/// blocks starts: a jump table of the function loaded a value that is none of the targets the
/// analysis found.
///
/// It is cold, out of line, and takes `target` by value, so the caller only passes a register. A
/// `panic!` written in the caller would format `target` through a reference, and taking that
/// reference makes the caller keep the value in memory.
#[cold]
#[inline(never)]
pub fn no_block(function: &'static str, target: u32) -> ! {
    panic!("{function}: no block at {target:#010x}")
}
