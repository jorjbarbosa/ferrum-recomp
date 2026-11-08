// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Errors of the runtime. Guest code never sees them: they come from setting the runtime up.

use std::io;

/// An error while setting up the runtime.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The system refused to map the guest address space, usually for lack of commit charge on
    /// Windows, where the whole region counts against it.
    #[error("cannot map {size:#x} bytes for the guest address space: {source}")]
    MapMemory {
        /// Bytes requested.
        size: usize,
        /// What the system reported.
        source: io::Error,
    },
    /// The system refused to protect the null-pointer guard at address 0.
    #[error("cannot protect the guard pages at guest address 0: {source}")]
    ProtectGuard {
        /// What the system reported.
        source: io::Error,
    },
    /// A function range was registered at an address that is not 4-aligned.
    #[error("the function range at {base:#010x} is not 4-aligned")]
    MisalignedRange {
        /// Where the range starts.
        base: u32,
    },
    /// A function range runs past the end of the 32-bit address space.
    #[error(
        "the function range at {base:#010x} with {len} entries runs past the end of the address space"
    )]
    RangeOverflow {
        /// Where the range starts.
        base: u32,
        /// How many entries it has.
        len: usize,
    },
    /// A function range overlaps one registered before.
    #[error("the function range {base:#010x}..{end:#x} overlaps the range at {other:#010x}")]
    OverlappingRange {
        /// Where the new range starts.
        base: u32,
        /// One past its last address.
        end: u64,
        /// Where the range it overlaps starts.
        other: u32,
    },
    /// An entry given to `FnTable::register_entries` that its range cannot hold.
    #[error("the function entry at {addr:#010x} {why}")]
    InvalidEntry {
        /// The address of the entry.
        addr: u32,
        /// What is wrong with it.
        why: &'static str,
    },
}
