// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use super::*;
use crate::test_support::{block, memory};

/// A time base that always reads the same value.
struct FixedTimeBase(u64);

impl TimeBase for FixedTimeBase {
    fn read(&self) -> u64 {
        self.0
    }
}

#[test]
fn a_new_context_is_zero_apart_from_msr_vscr_and_pvr() {
    let ctx = PpcContext::new();
    assert_eq!(ctx.r, [0; 32]);
    assert!(ctx.f.iter().all(|f| f.to_bits() == 0));
    assert_eq!(ctx.v, [V128::ZERO; 128]);
    assert_eq!((ctx.cr.to_u32(), ctx.xer.to_u32()), (0, 0));
    assert_eq!(
        (ctx.lr, ctx.ctr, ctx.fpscr.to_u32(), ctx.vrsave),
        (0, 0, 0, 0)
    );
    assert_eq!(ctx.msr, 0x0200_A000);
    assert_eq!(ctx.vscr.to_u32(), 0x0001_0000);
    assert_eq!(ctx.pvr, 0x0071_0700);
    assert_eq!(ctx.reserve, None);
}

#[test]
fn new_contexts_share_the_host_time_base() {
    let a = PpcContext::new();
    let b = PpcContext::default();
    assert!(std::ptr::addr_eq(
        Arc::as_ptr(&a.time_base),
        Arc::as_ptr(&b.time_base)
    ));
}

#[test]
fn mfspr_reads_each_register() {
    let mut ctx = PpcContext::with_time_base(Arc::new(FixedTimeBase(0x1234_5678_9ABC_DEF0)));
    ctx.xer = Xer::from_u32(0xA000_0011);
    ctx.lr = 0x8200_1018;
    ctx.ctr = 0xFFFF_FFFF_0000_0001;
    ctx.vrsave = 0xFFFF_0000;
    assert_eq!(ctx.mfspr(Spr::Xer), 0xA000_0011);
    assert_eq!(ctx.mfspr(Spr::Lr), 0x8200_1018);
    assert_eq!(ctx.mfspr(Spr::Ctr), 0xFFFF_FFFF_0000_0001);
    assert_eq!(ctx.mfspr(Spr::Vrsave), 0xFFFF_0000);
    assert_eq!(ctx.mfspr(Spr::Tbl), 0x1234_5678_9ABC_DEF0);
    assert_eq!(ctx.mfspr(Spr::Tbu), 0x1234_5678);
    assert_eq!(ctx.mfspr(Spr::Pvr), 0x0071_0700);
}

#[test]
fn mtspr_writes_each_writable_register() {
    let mut ctx = PpcContext::new();
    ctx.mtspr(Spr::Xer, 0xFFFF_FFFF_2000_0000);
    assert_eq!(
        ctx.xer,
        Xer {
            ca: true,
            ..Xer::default()
        }
    );
    assert_eq!(ctx.mfspr(Spr::Xer), 0x2000_0000);
    ctx.mtspr(Spr::Lr, 0x1234_5678);
    ctx.mtspr(Spr::Ctr, 0xABCD_EF01);
    ctx.mtspr(Spr::Vrsave, 0x1_FFFF_FFFF);
    assert_eq!(
        (ctx.lr, ctx.ctr, ctx.vrsave),
        (0x1234_5678, 0xABCD_EF01, 0xFFFF_FFFF)
    );
}

#[test]
#[should_panic(expected = "mtspr to the read-only register Tbl")]
fn mtspr_refuses_the_time_base() {
    PpcContext::new().mtspr(Spr::Tbl, 0);
}

#[test]
#[should_panic(expected = "mtspr to the read-only register Pvr")]
fn mtspr_refuses_the_pvr() {
    PpcContext::new().mtspr(Spr::Pvr, 0);
}

#[test]
fn a_reserved_word_is_stored_while_unchanged() {
    let mem = memory();
    let a = block();
    mem.write_u32(a, 0x1111_1111);
    let mut ctx = PpcContext::new();
    assert_eq!(ctx.load_reserved_u32(mem, a), 0x1111_1111);
    assert_eq!(
        ctx.reserve,
        Some(Reserve {
            addr: a,
            value: 0x1111_1111
        })
    );
    assert!(ctx.store_conditional_u32(mem, a, 0xABCD_EF12));
    assert_eq!(mem.read_u32(a), 0xABCD_EF12);
    assert_eq!(ctx.cr.to_u32(), 0x2000_0000);
    assert_eq!(ctx.reserve, None);
    // The reservation was used up.
    assert!(!ctx.store_conditional_u32(mem, a, 0x2222_2222));
    assert_eq!(mem.read_u32(a), 0xABCD_EF12);
    assert_eq!(ctx.cr.to_u32(), 0);
}

#[test]
fn a_store_conditional_without_a_reservation_fails() {
    let mem = memory();
    let a = block();
    let mut ctx = PpcContext::new();
    ctx.cr = Cr::from_u32(0xF000_0000);
    assert!(!ctx.store_conditional_u32(mem, a, 0x1234_5678));
    assert_eq!(mem.read_u32(a), 0);
    assert_eq!(ctx.cr.to_u32(), 0);
}

#[test]
fn a_store_conditional_to_another_address_fails_and_clears_the_reservation() {
    let mem = memory();
    let a = block();
    let mut ctx = PpcContext::new();
    ctx.load_reserved_u32(mem, a);
    assert!(!ctx.store_conditional_u32(mem, a + 4, 1));
    assert_eq!(mem.read_u32(a + 4), 0);
    assert_eq!(ctx.reserve, None);
    assert!(!ctx.store_conditional_u32(mem, a, 1));
    assert_eq!(mem.read_u32(a), 0);
}

#[test]
fn a_store_conditional_fails_when_another_thread_changed_the_word() {
    let mem = memory();
    let a = block();
    let mut ctx = PpcContext::new();
    ctx.load_reserved_u32(mem, a);
    mem.write_u32(a, 7);
    assert!(!ctx.store_conditional_u32(mem, a, 1));
    assert_eq!(mem.read_u32(a), 7);
}

#[test]
fn a_store_conditional_copies_so_into_cr0() {
    let mem = memory();
    let a = block();
    let mut ctx = PpcContext::new();
    ctx.xer.so = true;
    ctx.load_reserved_u32(mem, a);
    assert!(ctx.store_conditional_u32(mem, a, 1));
    assert_eq!(ctx.cr.field(0), Cr::EQ | Cr::SO);
    assert!(!ctx.store_conditional_u32(mem, a, 2));
    assert_eq!(ctx.cr.field(0), Cr::SO);
}

#[test]
fn doubleword_reservations_work_the_same_way() {
    let mem = memory();
    let a = block();
    mem.write_u64(a, 0x0102_0304_0506_0708);
    let mut ctx = PpcContext::new();
    assert_eq!(ctx.load_reserved_u64(mem, a), 0x0102_0304_0506_0708);
    assert!(ctx.store_conditional_u64(mem, a, 0xABCD_EF12_3456_7890));
    assert_eq!(mem.read_u64(a), 0xABCD_EF12_3456_7890);
    assert_eq!(ctx.cr.to_u32(), 0x2000_0000);
    ctx.load_reserved_u64(mem, a);
    mem.write_u64(a, 1);
    assert!(!ctx.store_conditional_u64(mem, a, 2));
    assert_eq!(mem.read_u64(a), 1);
}

#[test]
#[should_panic(expected = "reserved access of 4 bytes at unaligned address")]
fn lwarx_rejects_an_unaligned_address() {
    let a = block();
    PpcContext::new().load_reserved_u32(memory(), a + 1);
}

#[test]
#[should_panic(expected = "reserved access of 8 bytes at unaligned address")]
fn stdcx_rejects_an_unaligned_address() {
    let a = block();
    PpcContext::new().store_conditional_u64(memory(), a + 4, 0);
}

#[test]
fn reservations_make_a_counter_safe_across_threads() {
    const THREADS: u32 = 8;
    const ROUNDS: u32 = 2_000;
    let mem = memory();
    let counter = block();
    let start = AtomicBool::new(false);
    thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                let mut ctx = PpcContext::new();
                while !start.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                for _ in 0..ROUNDS {
                    // lwarx / addi / stwcx. / bne- loop
                    loop {
                        let value = ctx.load_reserved_u32(mem, counter);
                        if ctx.store_conditional_u32(mem, counter, value.wrapping_add(1)) {
                            break;
                        }
                    }
                }
            });
        }
        start.store(true, Ordering::Release);
    });
    assert_eq!(mem.read_u32(counter), THREADS * ROUNDS);
}

#[test]
fn mtmsr_changes_the_low_word_but_me() {
    let mut ctx = PpcContext::new();
    ctx.msr = 0xFFFF_FFFF_0000_1000;
    // EE and RI set, ME clear in the source: ME stays as it was.
    ctx.mtmsr(0x1234_5678_0000_8002, false);
    assert_eq!(ctx.msr, 0xFFFF_FFFF_0000_9002);
    ctx.mtmsr(0, false);
    assert_eq!(ctx.msr, 0xFFFF_FFFF_0000_1000);
    // PR also sets EE, IR and DR.
    ctx.mtmsr(0x4000, false);
    assert_eq!(ctx.msr, 0xFFFF_FFFF_0000_D030);
}

#[test]
fn mtmsr_with_l_writes_only_ee_and_ri() {
    let mut ctx = PpcContext::new();
    ctx.msr = 0x9030;
    ctx.mtmsr(0xFFFF_FFFF_FFFF_7FFD, true);
    assert_eq!(ctx.msr, 0x1030);
    ctx.mtmsrd(0x8002, true);
    assert_eq!(ctx.msr, 0x9032);
}

#[test]
fn mtmsrd_changes_every_bit_but_hv_and_me() {
    let mut ctx = PpcContext::new();
    ctx.msr = 0x1000_0000_0000_1000;
    ctx.mtmsrd(0, false);
    assert_eq!(ctx.msr, 0x1000_0000_0000_1000, "HV and ME stay");
    ctx.mtmsrd(u64::MAX, false);
    assert_eq!(ctx.msr, u64::MAX);
    // Bit 1 alone sets SF too.
    ctx.msr = 0;
    ctx.mtmsrd(0x4000_0000_0000_0000, false);
    assert_eq!(ctx.msr, 0xC000_0000_0000_0000);
}
