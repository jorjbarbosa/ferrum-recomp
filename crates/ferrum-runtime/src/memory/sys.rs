// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The system calls behind [`super::Memory`]: map a region, protect part of it, unmap it.

pub(super) use imp::{map, protect_none, unmap};

#[cfg(windows)]
mod imp {
    use std::io;
    use std::ptr::{self, NonNull};

    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
        VirtualAlloc, VirtualFree, VirtualProtect,
    };

    /// Reserves and commits `size` bytes of zeroed, readable and writable memory.
    pub(in crate::memory) fn map(size: usize) -> io::Result<NonNull<u8>> {
        // SAFETY: a null address asks the system for a fresh region, so no memory that Rust code
        // can see changes.
        let pointer =
            unsafe { VirtualAlloc(ptr::null(), size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        NonNull::new(pointer.cast::<u8>()).ok_or_else(io::Error::last_os_error)
    }

    /// Makes `len` bytes from `start` inaccessible.
    ///
    /// # Safety
    ///
    /// The range has to lie in a region returned by [`map`], and no reference may point into it.
    pub(in crate::memory) unsafe fn protect_none(start: NonNull<u8>, len: usize) -> io::Result<()> {
        let mut old: PAGE_PROTECTION_FLAGS = 0;
        // SAFETY: the caller guarantees that the range belongs to our mapping and that nothing
        // refers to it, so changing its protection cannot invalidate a live reference.
        let ok = unsafe { VirtualProtect(start.as_ptr().cast(), len, PAGE_NOACCESS, &mut old) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Releases a region returned by [`map`].
    ///
    /// # Safety
    ///
    /// `start` has to come from [`map`], and no reference may point into the region any more.
    pub(in crate::memory) unsafe fn unmap(start: NonNull<u8>, _size: usize) {
        // SAFETY: the caller guarantees that the region is ours and unused. MEM_RELEASE takes the
        // base address and a size of zero.
        let ok = unsafe { VirtualFree(start.as_ptr().cast(), 0, MEM_RELEASE) };
        debug_assert_ne!(ok, 0, "VirtualFree: {}", io::Error::last_os_error());
    }
}

#[cfg(unix)]
mod imp {
    use std::io;
    use std::ptr::{self, NonNull};

    /// Maps `size` bytes of zeroed, readable and writable memory without reserving swap for it.
    pub(in crate::memory) fn map(size: usize) -> io::Result<NonNull<u8>> {
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
        let protection = libc::PROT_READ | libc::PROT_WRITE;
        // SAFETY: a null address with an anonymous mapping asks the kernel for a fresh region, so
        // no memory that Rust code can see changes.
        let pointer = unsafe { libc::mmap(ptr::null_mut(), size, protection, flags, -1, 0) };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        NonNull::new(pointer.cast::<u8>()).ok_or_else(io::Error::last_os_error)
    }

    /// Makes `len` bytes from `start` inaccessible.
    ///
    /// # Safety
    ///
    /// The range has to lie in a region returned by [`map`], and no reference may point into it.
    pub(in crate::memory) unsafe fn protect_none(start: NonNull<u8>, len: usize) -> io::Result<()> {
        // SAFETY: the caller guarantees that the range belongs to our mapping and that nothing
        // refers to it, so changing its protection cannot invalidate a live reference.
        let result = unsafe { libc::mprotect(start.as_ptr().cast(), len, libc::PROT_NONE) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Releases a region returned by [`map`].
    ///
    /// # Safety
    ///
    /// `start` and `size` have to come from [`map`], and no reference may point into the region
    /// any more.
    pub(in crate::memory) unsafe fn unmap(start: NonNull<u8>, size: usize) {
        // SAFETY: the caller guarantees that the region is ours, with this size, and unused.
        let result = unsafe { libc::munmap(start.as_ptr().cast(), size) };
        debug_assert_eq!(result, 0, "munmap: {}", io::Error::last_os_error());
    }
}

#[cfg(not(any(windows, unix)))]
compile_error!(
    "ferrum-runtime maps guest memory with VirtualAlloc or mmap, so it needs Windows or Unix"
);
