// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Helpers shared by the unit tests of this crate.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::Memory;

/// Address of the first block that [`block`] hands out.
const FIRST_BLOCK: u32 = 0x2000_0000;
/// Distance between two blocks. Only the first [`BLOCK_SIZE`] bytes of each are registered, so
/// with the `trace` feature an access just past a block is outside every region.
const BLOCK_STRIDE: u32 = 0x2_0000;
/// Bytes a test may use from the start of its block.
pub(crate) const BLOCK_SIZE: u32 = 0x1_0000;

/// Returns the memory every test shares.
///
/// Each `Memory` commits 4 GiB on Windows, so tests never create their own: each one works in
/// blocks from [`block`] or at fixed addresses that no other test touches.
pub(crate) fn memory() -> &'static Memory {
    static MEMORY: OnceLock<Memory> = OnceLock::new();
    MEMORY.get_or_init(|| Memory::new().expect("map the memory shared by the tests"))
}

/// Returns the address of a fresh block of [`BLOCK_SIZE`] zeroed bytes that no other test uses,
/// registered as a region of [`memory`].
pub(crate) fn block() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let index = NEXT.fetch_add(1, Ordering::Relaxed);
    let base = index
        .checked_mul(BLOCK_STRIDE)
        .and_then(|offset| FIRST_BLOCK.checked_add(offset))
        .filter(|&base| base < 0x8000_0000)
        .expect("the tests asked for more blocks than fit below 0x80000000");
    memory().register_region(base, BLOCK_SIZE, "test block");
    base
}
