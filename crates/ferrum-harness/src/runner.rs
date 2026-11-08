// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Runs cases the way Xenia's harness does, on one [`Memory`] reset between cases.
//!
//! Each case gets the code at [`CODE_BASE`], the data region at [`DATA_BASE`], the stack below
//! `0x80000000` with r1 at its low end and the PCR under it, LR set to [`SENTINEL_LR`], and the MSR
//! Canary's test thread starts with.

use std::cell::{Cell, RefCell};
use std::panic::{self, AssertUnwindSafe, PanicHookInfo};
use std::sync::Once;

use ferrum_runtime::{FnTable, Kernels, Memory, PpcContext, Unimplemented, V128};

use crate::annotations::{Annotation, Case, Register};

/// Where the code of a test file is loaded.
pub const CODE_BASE: u32 = 0x8000_0000;
/// The end of the code region.
pub const CODE_END: u32 = 0x8001_0000;
/// The start of the data region, where the annotations put their bytes.
pub const DATA_BASE: u32 = 0x1000_1000;
/// The end of the data region: Xenia allocates `0xEFFF` bytes, which a page rounds up to this.
pub const DATA_END: u32 = 0x1001_0000;
/// The PCR, 4 KiB below the stack, which r13 points to.
pub const PCR_BASE: u32 = 0x7FFE_F000;
/// The low end of the 64 KiB stack, which r1 points to.
pub const STACK_BASE: u32 = 0x7FFF_0000;
/// LR when a case starts: the address a test returns to.
pub const SENTINEL_LR: u64 = 0xBCBC_BCBC;
/// The MSR of Canary's test thread, which its `instr_mfmsr` expects.
pub const TEST_MSR: u64 = 0x9030;

/// The regions a case may touch: code, data, and the PCR with the stack above it.
const REGIONS: [(u32, u32, &str); 3] = [
    (CODE_BASE, CODE_END, "code"),
    (DATA_BASE, DATA_END, "data"),
    (PCR_BASE, CODE_BASE, "pcr and stack"),
];

/// The bytes on either side of the regions that have to stay zero, without the `trace` feature.
#[cfg(not(feature = "trace"))]
const BANDS: [(u32, u32); 4] = [
    (DATA_BASE - 0x8000, DATA_BASE),
    (DATA_END, DATA_END + 0x8000),
    (PCR_BASE - 0x8000, PCR_BASE),
    (CODE_END, CODE_END + 0x8000),
];

/// One guest memory for every case, and what runs on it.
#[derive(Debug)]
pub struct Harness {
    mem: Memory,
}

impl Harness {
    /// Maps the memory and registers the regions, which the `trace` feature checks accesses
    /// against.
    pub fn new() -> Result<Self, ferrum_runtime::Error> {
        let mem = Memory::new()?;
        for (start, end, name) in REGIONS {
            mem.register_region(start, end - start, name);
        }
        install_panic_capture();
        Ok(Self { mem })
    }

    /// The memory.
    pub fn memory(&self) -> &Memory {
        &self.mem
    }

    /// Zeroes the regions, then loads `code` at [`CODE_BASE`].
    pub fn reset(&self, code: &[u8]) {
        for (start, end, _) in REGIONS {
            for addr in (start..end).step_by(8) {
                self.mem.write_u64(addr, 0);
            }
        }
        assert!(
            code.len() <= (CODE_END - CODE_BASE) as usize,
            "code too large"
        );
        self.mem.write_bytes(CODE_BASE, code);
    }

    /// A context as Xenia's test thread starts it.
    pub fn context() -> PpcContext {
        let mut ctx = PpcContext::new();
        ctx.r[1] = u64::from(STACK_BASE);
        ctx.r[13] = u64::from(PCR_BASE);
        ctx.msr = TEST_MSR;
        ctx.lr = SENTINEL_LR;
        ctx
    }

    /// Calls the function at `entry` from `table`, and returns the message of a panic if there is
    /// one.
    pub fn call(&self, ctx: &mut PpcContext, table: &FnTable, entry: u32) -> Result<(), String> {
        let kernels = Kernels {
            krnl: &Unimplemented,
            xam: &Unimplemented,
            table,
            hooks: ferrum_runtime::HookTable::empty(),
        };
        self.call_with(ctx, &kernels, entry)
    }

    /// Calls the function at `entry` from the table of `kernels`, with its kernel and hooks, and
    /// returns the message of a panic if there is one.
    pub fn call_with(
        &self,
        ctx: &mut PpcContext,
        kernels: &Kernels<'_>,
        entry: u32,
    ) -> Result<(), String> {
        let table = kernels.table;
        let function = table
            .get(entry)
            .ok_or_else(|| format!("no generated function at {entry:#010x}"))?;
        CAPTURING.set(true);
        let result = panic::catch_unwind(AssertUnwindSafe(|| function(ctx, &self.mem, kernels)));
        CAPTURING.set(false);
        result.map_err(|_| {
            CAPTURED
                .take()
                .unwrap_or_else(|| "a panic without a message".to_owned())
        })
    }

    /// Fails if a byte next to the regions is not zero, which means a write went outside them, and
    /// clears it for the next case. With the `trace` feature such a write panics instead.
    pub fn check_outside(&self) -> Result<(), String> {
        #[cfg(not(feature = "trace"))]
        for (start, end) in BANDS {
            for addr in (start..end).step_by(8) {
                if self.mem.read_u64(addr) != 0 {
                    for addr in (start..end).step_by(8) {
                        self.mem.write_u64(addr, 0);
                    }
                    return Err(format!(
                        "a write outside the harness's regions, near {addr:#010x}"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Runs one annotated case of a file whose functions are in `table`, from a reset with `code`,
    /// and returns what did not match. The case passes when the list is empty.
    pub fn run_case(&self, code: &[u8], table: &FnTable, case: &Case, entry: u32) -> Vec<String> {
        self.reset(code);
        let mut ctx = Self::context();
        let mut failures = Vec::new();
        for annotation in &case.annotations {
            match annotation {
                Annotation::RegisterIn(Register::Gpr(n), value) => ctx.r[usize::from(*n)] = *value,
                Annotation::RegisterIn(Register::Fpr(n), bits) => {
                    ctx.f[usize::from(*n)] = f64::from_bits(*bits);
                }
                Annotation::VectorIn(n, words) => ctx.v[usize::from(*n)] = V128(*words),
                Annotation::RegisterIn(Register::Cr, value) => match u32::try_from(*value) {
                    Ok(value) => ctx.cr = ferrum_runtime::Cr::from_u32(value),
                    Err(_) => failures.push(format!("cr input {value:#x} is wider than 32 bits")),
                },
                Annotation::MemoryIn(addr, bytes) => match in_data(*addr, bytes.len()) {
                    true => self.mem.write_bytes(*addr, bytes),
                    false => {
                        failures.push(format!("MEMORY_IN at {addr:#010x} outside the data region"))
                    }
                },
                Annotation::RegisterOut(..)
                | Annotation::VectorOut(..)
                | Annotation::MemoryOut(..) => {}
            }
        }
        if !failures.is_empty() {
            return failures;
        }
        ctx.lr = SENTINEL_LR;
        if let Err(message) = self.call(&mut ctx, table, entry) {
            failures.push(format!("panic: {message}"));
            // The bands may hold the start of a write that panicked; clear them either way.
            let _ = self.check_outside();
            return failures;
        }
        for annotation in &case.annotations {
            match annotation {
                Annotation::RegisterOut(register, expected) => {
                    // Every register is compared on its bits, an FPR included, so that -0.0
                    // differs from +0.0 and a NaN matches only its own pattern.
                    let (name, actual) = match register {
                        Register::Gpr(n) => (format!("r{n}"), ctx.r[usize::from(*n)]),
                        Register::Fpr(n) => (format!("f{n}"), ctx.f[usize::from(*n)].to_bits()),
                        Register::Cr => ("cr".to_owned(), u64::from(ctx.cr.to_u32())),
                    };
                    if actual != *expected {
                        let values = match register {
                            Register::Fpr(_) => format!(
                                " ({:e} against {:e})",
                                f64::from_bits(*expected),
                                f64::from_bits(actual)
                            ),
                            Register::Gpr(_) | Register::Cr => String::new(),
                        };
                        failures.push(format!(
                            "{name}: expected {expected:#018x}, got {actual:#018x}{values}"
                        ));
                    }
                }
                Annotation::VectorOut(n, expected) => {
                    // All 128 bits: a -0.0 lane differs from +0.0, and a NaN lane matches only
                    // its own pattern.
                    let actual = ctx.v[usize::from(*n)].0;
                    if actual != *expected {
                        failures.push(format!(
                            "v{n}: expected {}, got {}",
                            vector(expected),
                            vector(&actual)
                        ));
                    }
                }
                Annotation::MemoryOut(addr, expected) => {
                    if !in_data(*addr, expected.len()) {
                        failures.push(format!(
                            "MEMORY_OUT at {addr:#010x} outside the data region"
                        ));
                        continue;
                    }
                    let mut actual = vec![0; expected.len()];
                    self.mem.read_bytes(*addr, &mut actual);
                    if actual != *expected {
                        failures.push(format!(
                            "memory at {addr:#010x}: expected {}, got {}",
                            hex(expected),
                            hex(&actual)
                        ));
                    }
                }
                Annotation::RegisterIn(..)
                | Annotation::VectorIn(..)
                | Annotation::MemoryIn(..) => {}
            }
        }
        if let Err(message) = self.check_outside() {
            failures.push(message);
        }
        failures
    }
}

/// Whether `len` bytes at `addr` lie in the data region.
fn in_data(addr: u32, len: usize) -> bool {
    addr >= DATA_BASE && u64::from(addr) + len as u64 <= u64::from(DATA_END)
}

/// The four words of a vector, as the annotations write them.
fn vector(words: &[u32; 4]) -> String {
    let [w0, w1, w2, w3] = words;
    format!("[{w0:08X}, {w1:08X}, {w2:08X}, {w3:08X}]")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

thread_local! {
    /// Whether a panic on this thread is a case failing, to be captured rather than printed.
    static CAPTURING: Cell<bool> = const { Cell::new(false) };
    /// The message of the last captured panic.
    static CAPTURED: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Installs a panic hook that keeps the message of a panic inside [`Harness::call`] instead of
/// printing it, and leaves every other panic to the previous hook.
fn install_panic_capture() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info: &PanicHookInfo<'_>| {
            if CAPTURING.get() {
                CAPTURED.set(Some(message(info)));
            } else {
                previous(info);
            }
        }));
    });
}

fn message(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    let text = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with a payload that is not text".to_owned());
    match info.location() {
        Some(location) => format!("{text} ({}:{})", location.file(), location.line()),
        None => text,
    }
}
