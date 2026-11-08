// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! PowerPC decoder and disassembler for the Xbox 360 (Xenon) CPU.
//!
//! [`decode`] maps a 32-bit instruction word to an [`Insn`], one enum variant per opcode with typed
//! fields, including the VMX128 extensions. [`format`] and [`format_at`] print an instruction in
//! `objdump -Mpower7 -Mvmx128` syntax. The opcode table in [`OPCODES`] is the data behind both.
//!
//! The crate is independent of XEX parsing and code generation. It knows nothing about addresses
//! except the one [`format_at`] is given.
//!
//! The decoder covers PowerPC ISA 2.02, AltiVec and the Xenon extensions. Later additions that
//! objdump knows about, such as VSX or decimal floating point, are not Xenon instructions, so they
//! do not decode.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod decode;
mod fields;
mod format;
mod spr;
mod table;

pub use decode::decode;
pub use fields::{CrBit, CrField, Fpr, Gpr, Vr};
pub use format::{format, format_at, format_undecoded};
pub use table::{Form, Insn, OPCODES, Opcode, OpcodeInfo};

#[cfg(test)]
mod tests;
