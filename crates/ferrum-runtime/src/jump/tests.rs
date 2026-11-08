// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use std::panic;

use super::*;
use crate::test_support::memory;
use crate::{FnTable, Reserve, Unimplemented};

fn with_kernels(f: impl FnOnce(&Kernels<'_>)) {
    let table = FnTable::new();
    let kernels = Kernels {
        krnl: &Unimplemented,
        xam: &Unimplemented,
        table: &table,
        hooks: crate::HookTable::empty(),
    };
    f(&kernels);
}

/// Runs `f` and returns the payload it unwound with.
fn unwind(f: impl FnOnce()) -> Box<dyn Any + Send> {
    panic::catch_unwind(AssertUnwindSafe(f)).expect_err("it unwinds")
}

#[test]
fn longjmp_unwinds_with_the_low_words_and_turns_0_into_1() {
    with_kernels(|k| {
        let mut ctx = PpcContext::new();
        ctx.r[3] = 0xFFFF_FFFF_1000_2000;
        ctx.r[4] = 0x1234_5678_0000_0007;
        let payload = unwind(|| longjmp(&mut ctx, memory(), k));
        assert_eq!(
            *payload.downcast::<LongJmp>().unwrap(),
            LongJmp {
                buf: 0x1000_2000,
                value: 7
            }
        );
        ctx.r[4] = 0xFFFF_FFFF_0000_0000;
        let payload = unwind(|| longjmp(&mut ctx, memory(), k));
        assert_eq!(payload.downcast::<LongJmp>().unwrap().value, 1);
    });
}

#[test]
fn resume_puts_back_the_context_of_the_latest_setjmp_of_the_buffer() {
    let mut jumps = Jumps::new();
    let mut ctx = PpcContext::new();
    ctx.r[3] = 0x1000_0000;
    ctx.r[31] = 0x31;
    ctx.f[14] = 1.5;
    jumps.set(&ctx, 0x8200_0010);
    // A later setjmp with another buffer, and one with the first buffer again.
    ctx.r[3] = 0x1000_0100;
    jumps.set(&ctx, 0x8200_0020);
    ctx.r[3] = 0x1000_0000;
    ctx.r[31] = 0x3131;
    jumps.set(&ctx, 0x8200_0030);

    ctx.r[31] = 0xDEAD;
    ctx.f[14] = 0.0;
    ctx.reserve = Some(Reserve {
        addr: 0x1000,
        value: 0,
    });
    let payload: Box<dyn Any + Send> = Box::new(LongJmp {
        buf: 0x1000_0000,
        value: 0xFFFF_FFFE,
    });
    assert_eq!(jumps.resume(payload, &mut ctx), 0x8200_0030);
    assert_eq!(ctx.r[31], 0x3131, "the registers of the latest setjmp");
    assert_eq!(ctx.f[14], 1.5);
    assert_eq!(ctx.r[3], (-2i64) as u64, "the value, sign-extended");
    assert_eq!(ctx.reserve, None);

    let payload: Box<dyn Any + Send> = Box::new(LongJmp {
        buf: 0x1000_0100,
        value: 5,
    });
    assert_eq!(jumps.resume(payload, &mut ctx), 0x8200_0020);
    assert_eq!(ctx.r[3], 5);
}

#[test]
fn resume_passes_on_other_buffers_and_other_panics() {
    let mut jumps = Jumps::new();
    let mut ctx = PpcContext::new();
    ctx.r[3] = 0x1000_0000;
    jumps.set(&ctx, 0x8200_0010);
    let other = LongJmp {
        buf: 0x2000_0000,
        value: 1,
    };
    let payload = unwind(|| {
        jumps.resume(Box::new(other), &mut ctx);
    });
    assert_eq!(*payload.downcast::<LongJmp>().unwrap(), other);
    let payload = unwind(|| {
        jumps.resume(Box::new("a guest panic"), &mut ctx);
    });
    assert_eq!(*payload.downcast::<&str>().unwrap(), "a guest panic");
    assert_eq!(ctx.r[3], 0x1000_0000, "the context is left alone");
}

fn returns(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
    ctx.r[3] = 42;
}

fn jumps_nowhere(ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {
    ctx.r[3] = 0x1234_5678;
    ctx.r[4] = 1;
    longjmp(ctx, mem, k);
}

fn panics(_: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
    panic::resume_unwind(Box::new(7u8));
}

#[test]
fn enter_reports_a_longjmp_that_no_frame_resumes() {
    with_kernels(|k| {
        let mut ctx = PpcContext::new();
        enter(returns, &mut ctx, memory(), k);
        assert_eq!(ctx.r[3], 42);

        let payload = unwind(|| enter(jumps_nowhere, &mut ctx, memory(), k));
        let message = payload.downcast::<String>().unwrap();
        assert!(message.contains("0x12345678"), "{message}");

        let payload = unwind(|| enter(panics, &mut ctx, memory(), k));
        assert_eq!(*payload.downcast::<u8>().unwrap(), 7);
    });
}
