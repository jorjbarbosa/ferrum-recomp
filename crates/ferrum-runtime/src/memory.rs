// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Guest memory: the flat 32-bit address space, with a big-endian API that guest threads can share.
//!
//! The whole 4 GiB, plus [`SLACK`], is mapped once, so an access needs no bounds check: every
//! `u32` address is inside the mapping. Aligned accesses are relaxed atomics of their own size,
//! which compile to plain loads and stores; unaligned ones go byte by byte, also atomically.

use std::fmt;
use std::ptr::NonNull;
use std::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed};
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64};
use std::sync::{PoisonError, RwLock};

use crate::error::Error;
use crate::v128::V128;

mod sys;
#[cfg(test)]
mod tests;

/// Size of the guest address space: every `u32` is an address.
const ADDRESS_SPACE: usize = 1 << 32;

/// Bytes mapped past the end of the address space, so that an access of up to 16 bytes that starts
/// near `0xFFFF_FFFF` stays inside the mapping instead of wrapping to address 0.
pub const SLACK: usize = 64 * 1024;

/// Size of the inaccessible guard at guest address 0. A guest access below it faults, which turns
/// a null pointer into a crash at the access. 64 KiB is a whole number of host pages on every
/// supported host.
pub const GUARD_SIZE: u32 = 64 * 1024;

/// Bytes mapped in all.
const MAPPING_SIZE: usize = ADDRESS_SPACE + SLACK;

/// The guest address space.
///
/// One `Memory` serves every guest thread through `&Memory`. Reads and writes never fail: there is
/// no bounds check, and a guest access below [`GUARD_SIZE`] faults the host process. With the
/// `trace` feature every access is checked against the regions registered with
/// [`Memory::register_region`] instead, and one outside all of them panics.
///
/// The whole region counts against the commit charge on Windows; see the README.
pub struct Memory {
    /// Start of the mapping, which holds guest address 0.
    base: NonNull<u8>,
    /// Regions the port declared as allocated, which the `trace` feature checks accesses against.
    regions: RwLock<Vec<Region>>,
}

// SAFETY: `Memory` owns its mapping and frees it only in `drop`, which needs exclusive access.
// Every access to the mapped bytes is atomic, so sharing the pointer between threads creates no
// data race between accesses of the same size. Overlapping accesses of different sizes are
// mixed-size atomics, which Rust's memory model leaves undefined when they race; that takes two
// guest threads touching the same bytes with no synchronization, a data race in the guest too.
unsafe impl Send for Memory {}
// SAFETY: as above; `&Memory` only exposes atomic accesses and the lock-protected region list.
unsafe impl Sync for Memory {}

/// A range of guest addresses the port declared as allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    base: u32,
    size: u32,
    name: &'static str,
}

impl Region {
    /// Returns whether the `size` bytes at `addr` all lie in this region.
    #[cfg(any(feature = "trace", test))]
    fn contains(&self, addr: u32, size: usize) -> bool {
        let start = u64::from(addr);
        let end = start.saturating_add(size as u64);
        start >= u64::from(self.base) && end <= u64::from(self.base) + u64::from(self.size)
    }
}

impl Memory {
    /// Maps the guest address space, zeroed, with the guard at address 0.
    pub fn new() -> Result<Self, Error> {
        let base = sys::map(MAPPING_SIZE).map_err(|source| Error::MapMemory {
            size: MAPPING_SIZE,
            source,
        })?;
        debug_assert_eq!(
            base.as_ptr() as usize % 4096,
            0,
            "the mapping is page-aligned"
        );
        // Built before protecting the guard, so that an error below still unmaps the region.
        let memory = Self {
            base,
            regions: RwLock::new(Vec::new()),
        };
        // SAFETY: the guard is the start of the mapping just created, and no reference into the
        // mapping exists yet.
        unsafe { sys::protect_none(base, GUARD_SIZE as usize) }
            .map_err(|source| Error::ProtectGuard { source })?;
        Ok(memory)
    }

    /// Declares `size` bytes at `base` as allocated, under a name for diagnostics. Only the
    /// `trace` feature checks accesses against these regions; without it they are just recorded.
    pub fn register_region(&self, base: u32, size: u32, name: &'static str) {
        self.regions_mut().push(Region { base, size, name });
    }

    /// Removes the region registered at `base`, and returns whether there was one.
    pub fn unregister_region(&self, base: u32) -> bool {
        let mut regions = self.regions_mut();
        match regions.iter().position(|region| region.base == base) {
            Some(index) => {
                regions.remove(index);
                true
            }
            None => false,
        }
    }

    /// Reads the byte at `addr`.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn read_u8(&self, addr: u32) -> u8 {
        self.check(addr, 1);
        self.atomic_u8(addr as usize).load(Relaxed)
    }

    /// Reads the big-endian halfword at `addr`.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn read_u16(&self, addr: u32) -> u16 {
        self.check(addr, 2);
        let offset = addr as usize;
        if offset.is_multiple_of(2) {
            u16::from_be(self.atomic_u16(offset).load(Relaxed))
        } else {
            u16::from_be_bytes(self.load_bytes(offset))
        }
    }

    /// Reads the big-endian word at `addr`.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn read_u32(&self, addr: u32) -> u32 {
        self.check(addr, 4);
        let offset = addr as usize;
        if offset.is_multiple_of(4) {
            u32::from_be(self.atomic_u32(offset).load(Relaxed))
        } else {
            u32::from_be_bytes(self.load_bytes(offset))
        }
    }

    /// Reads the big-endian doubleword at `addr`.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn read_u64(&self, addr: u32) -> u64 {
        self.check(addr, 8);
        self.load_u64(addr as usize)
    }

    /// Reads the vector at `addr`, each lane a big-endian word. The address is used as given:
    /// clearing its low bits, as `lvx` does, is the caller's job.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn read_v128(&self, addr: u32) -> V128 {
        self.check(addr, 16);
        let offset = addr as usize;
        V128::from_halves(self.load_u64(offset), self.load_u64(offset + 8))
    }

    /// Writes the byte `value` at `addr`.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn write_u8(&self, addr: u32, value: u8) {
        self.check(addr, 1);
        self.atomic_u8(addr as usize).store(value, Relaxed);
    }

    /// Writes `value` at `addr` as a big-endian halfword.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn write_u16(&self, addr: u32, value: u16) {
        self.check(addr, 2);
        let offset = addr as usize;
        if offset.is_multiple_of(2) {
            self.atomic_u16(offset).store(value.to_be(), Relaxed);
        } else {
            self.store_bytes(offset, value.to_be_bytes());
        }
    }

    /// Writes `value` at `addr` as a big-endian word.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn write_u32(&self, addr: u32, value: u32) {
        self.check(addr, 4);
        let offset = addr as usize;
        if offset.is_multiple_of(4) {
            self.atomic_u32(offset).store(value.to_be(), Relaxed);
        } else {
            self.store_bytes(offset, value.to_be_bytes());
        }
    }

    /// Writes `value` at `addr` as a big-endian doubleword.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn write_u64(&self, addr: u32, value: u64) {
        self.check(addr, 8);
        self.store_u64(addr as usize, value);
    }

    /// Writes the vector `value` at `addr`, each lane as a big-endian word. The address is used as
    /// given, as for [`Memory::read_v128`].
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn write_v128(&self, addr: u32, value: V128) {
        self.check(addr, 16);
        let offset = addr as usize;
        let (high, low) = value.halves();
        self.store_u64(offset, high);
        self.store_u64(offset + 8, low);
    }

    /// Stores `new` at `addr` if the big-endian word there equals `current`, atomically, with
    /// acquire-release ordering. Returns the word found, as `Ok` if it was stored and `Err` if not.
    ///
    /// This is the store of `stwcx.`. Panics if `addr` is not 4-aligned: the hardware raises an
    /// alignment interrupt there, and interrupts are not supported.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn compare_exchange_u32(&self, addr: u32, current: u32, new: u32) -> Result<u32, u32> {
        self.check(addr, 4);
        if !addr.is_multiple_of(4) {
            misaligned_reservation(addr, 4);
        }
        self.atomic_u32(addr as usize)
            .compare_exchange(current.to_be(), new.to_be(), AcqRel, Acquire)
            .map(u32::from_be)
            .map_err(u32::from_be)
    }

    /// Stores `new` at `addr` if the big-endian doubleword there equals `current`, as
    /// [`Memory::compare_exchange_u32`] does for words. This is the store of `stdcx.`, and `addr`
    /// has to be 8-aligned.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn compare_exchange_u64(&self, addr: u32, current: u64, new: u64) -> Result<u64, u64> {
        self.check(addr, 8);
        if !addr.is_multiple_of(8) {
            misaligned_reservation(addr, 8);
        }
        self.atomic_u64(addr as usize)
            .compare_exchange(current.to_be(), new.to_be(), AcqRel, Acquire)
            .map(u64::from_be)
            .map_err(u64::from_be)
    }

    /// Copies `out.len()` bytes from `addr` into `out`, for loaders and tests. Addresses wrap at
    /// 4 GiB, so a copy that runs past `0xFFFF_FFFF` continues at address 0, in the guard.
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn read_bytes(&self, addr: u32, out: &mut [u8]) {
        for (index, byte) in out.iter_mut().enumerate() {
            // Truncating the index is the wrap at 4 GiB described above.
            let at = addr.wrapping_add(index as u32);
            self.check(at, 1);
            *byte = self.atomic_u8(at as usize).load(Relaxed);
        }
    }

    /// Copies `bytes` to `addr`, for loaders and tests. Addresses wrap at 4 GiB, as for
    /// [`Memory::read_bytes`].
    #[cfg_attr(feature = "trace", track_caller)]
    pub fn write_bytes(&self, addr: u32, bytes: &[u8]) {
        for (index, &byte) in bytes.iter().enumerate() {
            // Truncating the index is the wrap at 4 GiB described above.
            let at = addr.wrapping_add(index as u32);
            self.check(at, 1);
            self.atomic_u8(at as usize).store(byte, Relaxed);
        }
    }

    fn load_u64(&self, offset: usize) -> u64 {
        if offset.is_multiple_of(8) {
            u64::from_be(self.atomic_u64(offset).load(Relaxed))
        } else {
            u64::from_be_bytes(self.load_bytes(offset))
        }
    }

    fn store_u64(&self, offset: usize, value: u64) {
        if offset.is_multiple_of(8) {
            self.atomic_u64(offset).store(value.to_be(), Relaxed);
        } else {
            self.store_bytes(offset, value.to_be_bytes());
        }
    }

    /// Reads `N` bytes from `offset` one at a time: the path of unaligned accesses.
    fn load_bytes<const N: usize>(&self, offset: usize) -> [u8; N] {
        let mut bytes = [0; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = self.atomic_u8(offset + index).load(Relaxed);
        }
        bytes
    }

    /// Writes `N` bytes at `offset` one at a time: the path of unaligned accesses.
    fn store_bytes<const N: usize>(&self, offset: usize, bytes: [u8; N]) {
        for (index, byte) in bytes.into_iter().enumerate() {
            self.atomic_u8(offset + index).store(byte, Relaxed);
        }
    }

    /// Returns a pointer to the byte at `offset` from guest address 0.
    ///
    /// Every caller passes a guest address plus less than 16, so `offset` is below
    /// `ADDRESS_SPACE + 16`, inside the mapping thanks to [`SLACK`].
    #[inline(always)]
    fn byte_ptr(&self, offset: usize) -> *mut u8 {
        debug_assert!(
            offset < MAPPING_SIZE,
            "offset {offset:#x} outside the mapping"
        );
        // SAFETY: `offset` is inside the mapping (see above), so the result points into the same
        // allocation as `base`.
        unsafe { self.base.as_ptr().add(offset) }
    }

    #[inline(always)]
    fn atomic_u8(&self, offset: usize) -> &AtomicU8 {
        // SAFETY: the pointer is inside the mapping, which stays mapped while `self` is borrowed,
        // and a byte has no alignment requirement. Every access to guest memory is atomic. The
        // guard pages are part of the mapping but inaccessible: touching them faults, which is
        // what they are for.
        unsafe { AtomicU8::from_ptr(self.byte_ptr(offset)) }
    }

    #[inline(always)]
    fn atomic_u16(&self, offset: usize) -> &AtomicU16 {
        debug_assert!(offset.is_multiple_of(2));
        // SAFETY: as in `atomic_u8`; the mapping is page-aligned and callers pass an even offset,
        // so the pointer is aligned for `AtomicU16`.
        unsafe { AtomicU16::from_ptr(self.byte_ptr(offset).cast()) }
    }

    #[inline(always)]
    fn atomic_u32(&self, offset: usize) -> &AtomicU32 {
        debug_assert!(offset.is_multiple_of(4));
        // SAFETY: as in `atomic_u8`; the mapping is page-aligned and callers pass a multiple of 4,
        // so the pointer is aligned for `AtomicU32`.
        unsafe { AtomicU32::from_ptr(self.byte_ptr(offset).cast()) }
    }

    #[inline(always)]
    fn atomic_u64(&self, offset: usize) -> &AtomicU64 {
        debug_assert!(offset.is_multiple_of(8));
        // SAFETY: as in `atomic_u8`; the mapping is page-aligned and callers pass a multiple of 8,
        // so the pointer is aligned for `AtomicU64`.
        unsafe { AtomicU64::from_ptr(self.byte_ptr(offset).cast()) }
    }

    fn regions_mut(&self) -> std::sync::RwLockWriteGuard<'_, Vec<Region>> {
        // A panic while the lock was held cannot leave the list half-updated, so poisoning is
        // ignored.
        self.regions.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// With the `trace` feature, panics unless the `size` bytes at `addr` lie in one registered
    /// region. Without it, does nothing.
    #[inline(always)]
    #[cfg_attr(feature = "trace", track_caller)]
    fn check(&self, addr: u32, size: usize) {
        #[cfg(feature = "trace")]
        {
            let regions = self.regions.read().unwrap_or_else(PoisonError::into_inner);
            if !regions.iter().any(|region| region.contains(addr, size)) {
                drop(regions);
                access_outside_regions(addr, size);
            }
        }
        #[cfg(not(feature = "trace"))]
        let _ = (addr, size);
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        // SAFETY: the mapping came from `sys::map` with this size, and `&mut self` guarantees that
        // no reference into it is still alive.
        unsafe { sys::unmap(self.base, MAPPING_SIZE) };
    }
}

impl fmt::Debug for Memory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let regions = self.regions.read().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("Memory")
            .field("base", &self.base)
            .field("regions", &*regions)
            .finish()
    }
}

#[cold]
#[inline(never)]
#[cfg_attr(feature = "trace", track_caller)]
pub(crate) fn misaligned_reservation(addr: u32, size: u32) -> ! {
    panic!("reserved access of {size} bytes at unaligned address {addr:#010x}")
}

#[cfg(feature = "trace")]
#[cold]
#[inline(never)]
#[track_caller]
fn access_outside_regions(addr: u32, size: usize) -> ! {
    panic!("memory access outside every registered region: {size} bytes at {addr:#010x}")
}
