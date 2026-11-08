// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use super::*;
use crate::test_support::{block, memory};

/// Reads `N` bytes from guest memory.
fn bytes<const N: usize>(mem: &Memory, addr: u32) -> [u8; N] {
    let mut out = [0; N];
    mem.read_bytes(addr, &mut out);
    out
}

#[test]
fn every_width_is_big_endian() {
    let mem = memory();
    let a = block();
    mem.write_u16(a, 0x1122);
    mem.write_u32(a + 8, 0x1122_3344);
    mem.write_u64(a + 16, 0x1122_3344_5566_7788);
    assert_eq!(bytes::<2>(mem, a), [0x11, 0x22]);
    assert_eq!(bytes::<4>(mem, a + 8), [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(
        bytes::<8>(mem, a + 16),
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );

    mem.write_bytes(a + 32, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(mem.read_u8(a + 32), 1);
    assert_eq!(mem.read_u16(a + 32), 0x0102);
    assert_eq!(mem.read_u32(a + 32), 0x0102_0304);
    assert_eq!(mem.read_u64(a + 32), 0x0102_0304_0506_0708);
}

#[test]
fn unaligned_writes_land_on_their_bytes_only() {
    let mem = memory();
    let a = block();
    // Each case gets its own 32-byte slot; the value starts `shift` bytes into it.
    for (slot, shift) in (0..8u32).enumerate() {
        let start = a + slot as u32 * 32;
        mem.write_bytes(start, &[0xEE; 32]);
        let at = start + 8 + shift;
        mem.write_u64(at, 0x0102_0304_0506_0708);
        mem.write_u32(at + 8, 0x1112_1314);
        mem.write_u16(at + 12, 0x2122);
        let mut expected = [0xEE; 32];
        let body = [1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22];
        let from = 8 + shift as usize;
        expected[from..from + body.len()].copy_from_slice(&body);
        assert_eq!(bytes::<32>(mem, start), expected, "shift {shift}");
        assert_eq!(mem.read_u64(at), 0x0102_0304_0506_0708, "shift {shift}");
        assert_eq!(mem.read_u32(at + 8), 0x1112_1314, "shift {shift}");
        assert_eq!(mem.read_u16(at + 12), 0x2122, "shift {shift}");
    }
}

#[test]
fn aligned_and_unaligned_reads_agree_with_the_bytes() {
    let mem = memory();
    let a = block();
    let pattern: Vec<u8> = (0..40u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    mem.write_bytes(a, &pattern);
    for offset in 0..16usize {
        let addr = a + offset as u32;
        let at = |n: usize| &pattern[offset..offset + n];
        let half = u16::from_be_bytes(at(2).try_into().unwrap());
        let word = u32::from_be_bytes(at(4).try_into().unwrap());
        let double = u64::from_be_bytes(at(8).try_into().unwrap());
        assert_eq!(mem.read_u16(addr), half, "offset {offset}");
        assert_eq!(mem.read_u32(addr), word, "offset {offset}");
        assert_eq!(mem.read_u64(addr), double, "offset {offset}");
    }
}

#[test]
fn vectors_keep_lane_order_at_any_alignment() {
    let mem = memory();
    let a = block();
    let value = V128([0x0011_2233, 0x4455_6677, 0x8899_AABB, 0xCCDD_EEFF]);
    let expected = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    for (slot, shift) in [0u32, 8, 4, 1, 3, 15].into_iter().enumerate() {
        let at = a + slot as u32 * 64 + shift;
        mem.write_v128(at, value);
        assert_eq!(bytes::<16>(mem, at), expected, "shift {shift}");
        assert_eq!(mem.read_v128(at), value, "shift {shift}");
        assert_eq!(mem.read_u32(at + 12), 0xCCDD_EEFF, "shift {shift}");
    }
}

#[cfg(not(feature = "trace"))]
#[test]
fn accesses_at_the_top_of_the_address_space_use_the_slack() {
    // The only test that touches the last page of the address space.
    let mem = memory();
    mem.write_u64(0xFFFF_FFFC, 0x1122_3344_5566_7788);
    assert_eq!(mem.read_u64(0xFFFF_FFFC), 0x1122_3344_5566_7788);
    assert_eq!(mem.read_u32(0xFFFF_FFFC), 0x1122_3344);
    let value = V128([1, 2, 3, 4]);
    mem.write_v128(0xFFFF_FFF8, value);
    assert_eq!(mem.read_v128(0xFFFF_FFF8), value);
    mem.write_u16(0xFFFF_FFFF, 0xABCD);
    assert_eq!(mem.read_u16(0xFFFF_FFFF), 0xABCD);
}

#[test]
fn the_guard_ends_at_64_kib() {
    // The only test that touches the page after the guard.
    let mem = memory();
    mem.register_region(GUARD_SIZE, 0x100, "after the guard");
    assert_eq!(mem.read_u8(GUARD_SIZE), 0);
    mem.write_u32(GUARD_SIZE, 0xDEAD_BEEF);
    assert_eq!(mem.read_u32(GUARD_SIZE), 0xDEAD_BEEF);
}

/// Name of the variable that makes `the_guard_faults` read the address it holds and exit.
const GUARD_CHILD: &str = "FERRUM_RUNTIME_GUARD_CHILD";

#[test]
fn the_guard_faults() {
    if let Ok(addr) = std::env::var(GUARD_CHILD) {
        let addr: u32 = addr.parse().expect("an address in decimal");
        let mem = Memory::new().expect("map the memory of the child");
        // With `trace`, the check would panic before the access could fault.
        mem.register_region(0, GUARD_SIZE, "guard");
        std::hint::black_box(mem.read_u8(addr));
        std::process::exit(0);
    }
    for addr in [0, GUARD_SIZE - 1] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "memory::tests::the_guard_faults",
                "--test-threads=1",
            ])
            .env(GUARD_CHILD, addr.to_string())
            .output()
            .expect("run the test binary again")
            .status;
        assert!(
            died_of_an_access_fault(&status),
            "address {addr:#x}: {status}"
        );
    }
}

#[cfg(windows)]
fn died_of_an_access_fault(status: &std::process::ExitStatus) -> bool {
    // STATUS_ACCESS_VIOLATION, which a process killed by the fault exits with.
    status.code() == Some(0xC000_0005_u32 as i32)
}

#[cfg(unix)]
fn died_of_an_access_fault(status: &std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    matches!(status.signal(), Some(libc::SIGSEGV | libc::SIGBUS))
}

#[test]
fn compare_exchange_stores_only_on_a_match() {
    let mem = memory();
    let a = block();
    mem.write_u32(a, 5);
    assert_eq!(mem.compare_exchange_u32(a, 5, 0x0102_0304), Ok(5));
    assert_eq!(bytes::<4>(mem, a), [1, 2, 3, 4]);
    assert_eq!(mem.compare_exchange_u32(a, 5, 9), Err(0x0102_0304));
    assert_eq!(mem.read_u32(a), 0x0102_0304);

    mem.write_u64(a + 8, 6);
    assert_eq!(
        mem.compare_exchange_u64(a + 8, 6, 0x0102_0304_0506_0708),
        Ok(6)
    );
    assert_eq!(bytes::<8>(mem, a + 8), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        mem.compare_exchange_u64(a + 8, 6, 9),
        Err(0x0102_0304_0506_0708)
    );
    assert_eq!(mem.read_u64(a + 8), 0x0102_0304_0506_0708);
}

#[test]
#[should_panic(expected = "reserved access of 4 bytes at unaligned address")]
fn compare_exchange_rejects_an_unaligned_word() {
    let mem = memory();
    let a = block();
    let _ = mem.compare_exchange_u32(a + 2, 0, 1);
}

#[test]
#[should_panic(expected = "reserved access of 8 bytes at unaligned address")]
fn compare_exchange_rejects_an_unaligned_doubleword() {
    let mem = memory();
    let a = block();
    let _ = mem.compare_exchange_u64(a + 4, 0, 1);
}

#[test]
fn concurrent_increments_are_not_lost() {
    const THREADS: u32 = 8;
    const ROUNDS: u32 = 5_000;
    let mem = memory();
    let counter = block();
    let start = AtomicBool::new(false);
    thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                while !start.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                for _ in 0..ROUNDS {
                    let mut seen = mem.read_u32(counter);
                    while let Err(actual) = mem.compare_exchange_u32(counter, seen, seen + 1) {
                        seen = actual;
                    }
                }
            });
        }
        start.store(true, Ordering::Release);
    });
    assert_eq!(mem.read_u32(counter), THREADS * ROUNDS);
}

#[test]
fn regions_can_be_removed() {
    let mem = memory();
    mem.register_region(0x7000_0000, 0x10, "removed");
    assert!(mem.unregister_region(0x7000_0000));
    assert!(!mem.unregister_region(0x7000_0000));
}

#[test]
fn a_region_contains_only_accesses_that_fit_in_it() {
    let region = Region {
        base: 0x1000,
        size: 0x10,
        name: "test",
    };
    assert!(region.contains(0x1000, 16));
    assert!(region.contains(0x100F, 1));
    assert!(!region.contains(0x100F, 2));
    assert!(!region.contains(0x0FFF, 1));
    assert!(!region.contains(0x1010, 1));
    let top = Region {
        base: 0xFFFF_FFF0,
        size: 0x10,
        name: "top",
    };
    assert!(top.contains(0xFFFF_FFFF, 1));
    assert!(!top.contains(0xFFFF_FFFF, 2));
}

#[cfg(feature = "trace")]
mod trace {
    use std::cell::{Cell, RefCell};
    use std::panic::{self, AssertUnwindSafe, Location};
    use std::sync::Once;

    use super::*;
    use crate::test_support::BLOCK_SIZE;

    thread_local! {
        /// Whether a panic on this thread is expected, and its location is to be recorded
        /// instead of printed.
        static EXPECTING: Cell<bool> = const { Cell::new(false) };
        /// Location of the last expected panic on this thread.
        static LOCATION: RefCell<String> = const { RefCell::new(String::new()) };
    }

    /// Runs `access` and returns the message and location of the panic it has to raise.
    fn panic_of(access: impl FnOnce()) -> (String, String) {
        static HOOK: Once = Once::new();
        HOOK.call_once(|| {
            let previous = panic::take_hook();
            panic::set_hook(Box::new(move |info| {
                if EXPECTING.get() {
                    let location = info
                        .location()
                        .map(|l| format!("{}:{}", l.file(), l.line()))
                        .unwrap_or_default();
                    LOCATION.set(location);
                } else {
                    previous(info);
                }
            }));
        });
        EXPECTING.set(true);
        let payload = panic::catch_unwind(AssertUnwindSafe(access));
        EXPECTING.set(false);
        let payload = payload.expect_err("the access should panic");
        let message = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        (message, LOCATION.take())
    }

    #[test]
    fn an_access_past_a_region_panics_where_it_was_made() {
        let mem = memory();
        let a = block();
        mem.write_u32(a + BLOCK_SIZE - 4, 1);
        let line = Location::caller().line() + 1;
        let (message, location) = panic_of(|| _ = mem.read_u32(a + BLOCK_SIZE - 2));
        let addr = a + BLOCK_SIZE - 2;
        assert_eq!(
            message,
            format!("memory access outside every registered region: 4 bytes at {addr:#010x}")
        );
        assert_eq!(location, format!("{}:{line}", file!()));
    }

    #[test]
    fn an_unregistered_region_is_no_longer_accessible() {
        let mem = memory();
        mem.register_region(0x7100_0000, 0x10, "temporary");
        mem.write_u8(0x7100_0000, 1);
        assert!(mem.unregister_region(0x7100_0000));
        let (message, _) = panic_of(|| mem.write_u8(0x7100_0000, 2));
        assert!(message.contains("1 bytes at 0x71000000"), "{message}");
    }

    #[test]
    fn an_access_into_the_slack_is_outside_every_region() {
        let mem = memory();
        let (message, _) = panic_of(|| _ = mem.read_u64(0xFFFF_FFFC));
        assert!(message.contains("8 bytes at 0xfffffffc"), "{message}");
    }
}
