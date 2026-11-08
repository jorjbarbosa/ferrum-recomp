// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The guest CPU state of one thread.

use std::fmt;
use std::sync::Arc;

use crate::memory::misaligned_reservation;
use crate::registers::{Cr, Xer};
use crate::spr::Spr;
use crate::time_base::{TimeBase, host_time_base};
use crate::{Fpscr, Memory, V128, Vscr};

#[cfg(test)]
mod tests;

/// The MSR a new context starts with: FP and VMX available, external interrupts enabled.
pub const INITIAL_MSR: u64 = 0x0200_A000;

/// The PVR a new context reports: the value Xenia uses by default (`src/xenia/cpu/cpu_flags.cc`,
/// which also lists `0x710800` for later consoles).
pub const XENON_PVR: u32 = 0x0071_0700;

/// A reservation taken by `lwarx` or `ldarx`: the address and the value loaded from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reserve {
    /// The address that was loaded.
    pub addr: u32,
    /// The value loaded, zero-extended for `lwarx`.
    pub value: u64,
}

/// The registers of one guest thread, which generated code reads and writes directly.
///
/// One context belongs to one host thread. The port gives each guest thread its stack and PCR
/// (`r13`) in [`Memory`] when it creates the thread.
#[derive(Clone)]
pub struct PpcContext {
    /// General-purpose registers.
    pub r: [u64; 32],
    /// Floating-point registers.
    pub f: [f64; 32],
    /// Vector registers, 128 with VMX128.
    pub v: [V128; 128],
    /// Condition register.
    pub cr: Cr,
    /// Fixed-point exception register.
    pub xer: Xer,
    /// Link register.
    pub lr: u64,
    /// Count register.
    pub ctr: u64,
    /// Floating-point status and control register.
    pub fpscr: Fpscr,
    /// Vector status and control register; starts with NJ set, in non-Java mode.
    pub vscr: Vscr,
    /// Vector save register.
    pub vrsave: u32,
    /// Machine state register; starts at [`INITIAL_MSR`].
    pub msr: u64,
    /// Processor version register, read-only to the guest; starts at [`XENON_PVR`].
    pub pvr: u32,
    /// The reservation of the last `lwarx`/`ldarx`, until a `stwcx.`/`stdcx.` uses it.
    pub reserve: Option<Reserve>,
    /// The clock that `mftb` reads, shared with the other threads.
    pub time_base: Arc<dyn TimeBase>,
}

impl PpcContext {
    /// Returns a context with every register zero except the MSR, VSCR and PVR, reading the
    /// process's [`crate::HostTimeBase`].
    pub fn new() -> Self {
        Self::with_time_base(host_time_base())
    }

    /// Returns a context like [`PpcContext::new`] that reads `time_base` instead.
    pub fn with_time_base(time_base: Arc<dyn TimeBase>) -> Self {
        Self {
            r: [0; 32],
            f: [0.0; 32],
            v: [V128::ZERO; 128],
            cr: Cr::default(),
            xer: Xer::default(),
            lr: 0,
            ctr: 0,
            fpscr: Fpscr::default(),
            vscr: Vscr::default(),
            vrsave: 0,
            msr: INITIAL_MSR,
            pvr: XENON_PVR,
            reserve: None,
            time_base,
        }
    }

    /// Returns the value of `spr`, as `mfspr` and `mftb` read it.
    pub fn mfspr(&self, spr: Spr) -> u64 {
        match spr {
            Spr::Xer => u64::from(self.xer.to_u32()),
            Spr::Lr => self.lr,
            Spr::Ctr => self.ctr,
            Spr::Vrsave => u64::from(self.vrsave),
            Spr::Tbl => self.time_base.read(),
            Spr::Tbu => self.time_base.read() >> 32,
            Spr::Pvr => u64::from(self.pvr),
        }
    }

    /// Writes `value` to `spr`, as `mtspr` does. XER and VRSAVE keep the low word.
    ///
    /// Panics for a read-only register; codegen never emits one, because [`Spr::for_mtspr`]
    /// rejects them.
    pub fn mtspr(&mut self, spr: Spr, value: u64) {
        match spr {
            // Both registers are 32 bits wide, so the truncations are intended.
            Spr::Xer => self.xer = Xer::from_u32(value as u32),
            Spr::Vrsave => self.vrsave = value as u32,
            Spr::Lr => self.lr = value,
            Spr::Ctr => self.ctr = value,
            Spr::Tbl | Spr::Tbu | Spr::Pvr => read_only_spr(spr),
        }
    }

    /// `mtmsr`: writes the MSR from `value` as Book III says. With `l` (L=1) only EE and RI change.
    /// Otherwise bits 32:63 change except ME, and EE, IR and DR are also set when PR is.
    pub fn mtmsr(&mut self, value: u64, l: bool) {
        self.msr = if l {
            write_ee_ri(self.msr, value)
        } else {
            write_msr(self.msr, value, MTMSR_COPY)
        };
    }

    /// `mtmsrd`: writes the MSR from `value` as Book III says. With `l` (L=1, which Xenon also names
    /// `mtmsree`) only EE and RI change. Otherwise every bit changes except HV and ME, EE, IR and
    /// DR are also set when PR is, and SF is set when either of the two top bits of `value` is.
    pub fn mtmsrd(&mut self, value: u64, l: bool) {
        self.msr = if l {
            write_ee_ri(self.msr, value)
        } else {
            let msr = write_msr(self.msr, value, MTMSRD_COPY);
            let sf = if value & (msr_bit(0) | msr_bit(1)) != 0 {
                msr_bit(0)
            } else {
                0
            };
            (msr & !msr_bit(0)) | sf
        };
    }

    /// Loads the word at `addr` and takes a reservation on it: `lwarx`.
    ///
    /// Panics if `addr` is not 4-aligned, where the hardware raises an alignment interrupt.
    pub fn load_reserved_u32(&mut self, mem: &Memory, addr: u32) -> u32 {
        if !addr.is_multiple_of(4) {
            misaligned_reservation(addr, 4);
        }
        let value = mem.read_u32(addr);
        self.reserve = Some(Reserve {
            addr,
            value: u64::from(value),
        });
        value
    }

    /// Loads the doubleword at `addr` and takes a reservation on it: `ldarx`.
    ///
    /// Panics if `addr` is not 8-aligned, where the hardware raises an alignment interrupt.
    pub fn load_reserved_u64(&mut self, mem: &Memory, addr: u32) -> u64 {
        if !addr.is_multiple_of(8) {
            misaligned_reservation(addr, 8);
        }
        let value = mem.read_u64(addr);
        self.reserve = Some(Reserve { addr, value });
        value
    }

    /// Stores `value` at `addr` if this thread holds a reservation on `addr` and the word there
    /// still equals the one reserved: `stwcx.`. Returns whether it stored.
    ///
    /// Clears the reservation either way, and sets CR0 to `0b00 || stored || XER[SO]`. A store
    /// by another thread is detected by comparing values, so one that writes back the reserved
    /// value goes unseen. Panics if `addr` is not 4-aligned.
    pub fn store_conditional_u32(&mut self, mem: &Memory, addr: u32, value: u32) -> bool {
        if !addr.is_multiple_of(4) {
            misaligned_reservation(addr, 4);
        }
        let stored = match self.reserve.take() {
            // `lwarx` zero-extended the word it reserved, so the cast gives it back unchanged.
            Some(reserve) if reserve.addr == addr => mem
                .compare_exchange_u32(addr, reserve.value as u32, value)
                .is_ok(),
            _ => false,
        };
        self.record_store_conditional(stored);
        stored
    }

    /// Stores `value` at `addr` as [`PpcContext::store_conditional_u32`] does, for a doubleword:
    /// `stdcx.`. Panics if `addr` is not 8-aligned.
    pub fn store_conditional_u64(&mut self, mem: &Memory, addr: u32, value: u64) -> bool {
        if !addr.is_multiple_of(8) {
            misaligned_reservation(addr, 8);
        }
        let stored = match self.reserve.take() {
            Some(reserve) if reserve.addr == addr => {
                mem.compare_exchange_u64(addr, reserve.value, value).is_ok()
            }
            _ => false,
        };
        self.record_store_conditional(stored);
        stored
    }

    /// Writes CR0 after a store conditional.
    fn record_store_conditional(&mut self, stored: bool) {
        let mut field = if stored { Cr::EQ } else { 0 };
        if self.xer.so {
            field |= Cr::SO;
        }
        self.cr.set_field(0, field);
    }
}

impl Default for PpcContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PpcContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PpcContext")
            .field("r", &self.r)
            .field("f", &self.f)
            .field("v", &self.v)
            .field("cr", &self.cr)
            .field("xer", &self.xer)
            .field("lr", &self.lr)
            .field("ctr", &self.ctr)
            .field("fpscr", &self.fpscr)
            .field("vscr", &self.vscr)
            .field("vrsave", &self.vrsave)
            .field("msr", &self.msr)
            .field("pvr", &self.pvr)
            .field("reserve", &self.reserve)
            .finish_non_exhaustive()
    }
}

/// The MSR bit that the ISA numbers `n`, counting from the most significant bit.
const fn msr_bit(n: u32) -> u64 {
    1 << (63 - n)
}

/// The MSR bits from `first` to `last`, numbered as in the ISA.
const fn msr_bits(first: u32, last: u32) -> u64 {
    let mut bits = 0;
    let mut n = first;
    while n <= last {
        bits |= msr_bit(n);
        n += 1;
    }
    bits
}

const MSR_EE: u64 = msr_bit(48);
const MSR_PR: u64 = msr_bit(49);
const MSR_IR: u64 = msr_bit(58);
const MSR_DR: u64 = msr_bit(59);
const MSR_RI: u64 = msr_bit(62);

/// The bits `mtmsr` with L=0 copies from the source register.
const MTMSR_COPY: u64 = msr_bits(32, 47) | msr_bits(49, 50) | msr_bits(52, 57) | msr_bits(60, 63);

/// The bits `mtmsrd` with L=0 copies from the source register.
const MTMSRD_COPY: u64 =
    msr_bits(1, 2) | msr_bits(4, 47) | msr_bits(49, 50) | msr_bits(52, 57) | msr_bits(60, 63);

/// The MSR after an `mtmsr` or `mtmsrd` with L=0: the `copy` bits come from `value`, and EE, IR
/// and DR are each the OR of their own bit and PR.
fn write_msr(msr: u64, value: u64, copy: u64) -> u64 {
    let pr = value & MSR_PR != 0;
    let with_pr = |bit: u64| if value & bit != 0 || pr { bit } else { 0 };
    let set = (value & copy) | with_pr(MSR_EE) | with_pr(MSR_IR) | with_pr(MSR_DR);
    (msr & !(copy | MSR_EE | MSR_IR | MSR_DR)) | set
}

/// The MSR after an `mtmsr` or `mtmsrd` with L=1: only EE and RI come from `value`.
fn write_ee_ri(msr: u64, value: u64) -> u64 {
    (msr & !(MSR_EE | MSR_RI)) | (value & (MSR_EE | MSR_RI))
}

#[cold]
#[inline(never)]
fn read_only_spr(spr: Spr) -> ! {
    panic!("mtspr to the read-only register {spr:?}")
}
