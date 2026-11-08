// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! `setjmp` and `longjmp` across recompiled frames, by unwinding.
//!
//! A guest call is a host call, so a `longjmp` has to drop the host frames between it and its
//! `setjmp`. [`longjmp`] unwinds with a [`LongJmp`] payload; a generated function that calls
//! `setjmp` runs its body under `catch_unwind` and keeps a [`Jumps`], which puts back the context
//! of the matching `setjmp` and says where to resume. [`enter`] reports a `longjmp` that no frame
//! resumes.

use std::any::Any;
use std::panic::{self, AssertUnwindSafe};

use crate::{GuestFn, Kernels, Memory, PpcContext};

/// The payload of the unwinding that [`longjmp`] starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongJmp {
    /// The guest address of the `jmp_buf`.
    pub buf: u32,
    /// The value `setjmp` returns the second time, never 0.
    pub value: u32,
}

/// The guest's `longjmp(env, value)`: unwinds to the frame whose latest `setjmp` used the buffer
/// at the low word of r3, which then returns the low word of r4 from that `setjmp`, or 1 if it is
/// 0, as C requires.
///
/// It never returns. Its signature is the one of every guest function, so that the function table
/// can hold it. `std::panic::resume_unwind` does not run the panic hook, so nothing is printed.
pub fn longjmp(ctx: &mut PpcContext, _mem: &Memory, _k: &Kernels<'_>) {
    // The low words: the guest runs in 32-bit mode, and C passes an int.
    let buf = ctx.r[3] as u32;
    let value = match ctx.r[4] as u32 {
        0 => 1,
        value => value,
    };
    panic::resume_unwind(Box::new(LongJmp { buf, value }))
}

/// What one invocation of a generated function that calls `setjmp` keeps: for each buffer, the
/// context of its latest `setjmp` and the address after that call.
///
/// Generated code calls [`Jumps::set`] before each call to `setjmp`, and [`Jumps::resume`] when its
/// body unwinds.
#[derive(Default)]
pub struct Jumps {
    saved: Vec<Saved>,
}

/// The state of one `setjmp`.
struct Saved {
    buf: u32,
    resume: u32,
    ctx: Box<PpcContext>,
}

impl Jumps {
    /// Returns an empty record.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a call to `setjmp`, about to be made with `ctx`: its buffer, at the low word of r3,
    /// a copy of every register, and `resume`, the address after the call. A later `setjmp` with
    /// the same buffer replaces it.
    pub fn set(&mut self, ctx: &PpcContext, resume: u32) {
        // The low word: an address in 32-bit mode.
        let buf = ctx.r[3] as u32;
        let saved = Saved {
            buf,
            resume,
            ctx: Box::new(ctx.clone()),
        };
        match self.saved.iter_mut().find(|saved| saved.buf == buf) {
            Some(old) => *old = saved,
            None => self.saved.push(saved),
        }
    }

    /// Handles the payload of an unwinding that reached this frame. A [`LongJmp`] to a buffer
    /// this frame set puts back the context of that `setjmp`, writes the value into r3 and
    /// returns the address to resume at. Any other payload goes on unwinding.
    ///
    /// The value is a C int, so r3 holds it sign-extended, as the ABI keeps ints in 64-bit
    /// registers. The reservation is dropped, since no `stwcx.` may pair with an earlier `lwarx`.
    pub fn resume(&self, payload: Box<dyn Any + Send>, ctx: &mut PpcContext) -> u32 {
        let jump = match payload.downcast::<LongJmp>() {
            Ok(jump) => jump,
            Err(other) => panic::resume_unwind(other),
        };
        let Some(saved) = self.saved.iter().find(|saved| saved.buf == jump.buf) else {
            panic::resume_unwind(jump)
        };
        *ctx = (*saved.ctx).clone();
        // Reinterpreting the int and widening it with its sign is the intent.
        ctx.r[3] = jump.value as i32 as i64 as u64;
        ctx.reserve = None;
        saved.resume
    }
}

/// Runs the guest function `f` as the outermost frame of a guest thread. A `longjmp` that no frame
/// resumes means that no live frame set its buffer, which C leaves undefined: it becomes a panic
/// that names the buffer. Any other unwinding goes on.
pub fn enter(f: GuestFn, ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {
    let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| f(ctx, mem, k))) else {
        return;
    };
    match payload.downcast::<LongJmp>() {
        Ok(jump) => no_frame(&jump),
        Err(other) => panic::resume_unwind(other),
    }
}

#[cold]
#[inline(never)]
fn no_frame(jump: &LongJmp) -> ! {
    panic!(
        "longjmp to the buffer at {:#010x}, which no live frame set",
        jump.buf
    )
}

#[cfg(test)]
mod tests;
