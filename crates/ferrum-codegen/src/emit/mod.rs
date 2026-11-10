// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The `emit_*` side of code generation: the Rust statements for one instruction.
//!
//! Each family module handles its opcodes and says whether it knew the instruction. One that no
//! family knows is counted as an opcode without `emit_*`, and generation goes on, so that the
//! error lists every missing opcode at once.

mod float;
mod integer;
mod memory;
mod rotate;
mod system;
mod vector;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use ferrum_analysis::Function;
use ferrum_decoder::{Fpr, Gpr, Insn};

use crate::error::Error;
use crate::program::{ControlFlow, Program, function_name};
use crate::sites::{Site, SiteKind};
use crate::structured::placeholder;

/// Collects the text of one generated function.
pub(crate) struct Emitter<'a> {
    pub(crate) program: &'a Program<'a>,
    pub(crate) function: Function,
    /// The entries of the functions in the same crate, which are called directly.
    pub(crate) local: RangeInclusive<u32>,
    /// How the function follows its branches, which decides how a site is written.
    pub(crate) control_flow: ControlFlow,
    text: String,
    depth: usize,
    missing: BTreeMap<String, usize>,
    /// The start of the block being written.
    block: u32,
    /// The sites of that block, from [`crate::sites::transfers`].
    sites: Vec<Site>,
    /// How many of them the code has written.
    taken: usize,
}

impl<'a> Emitter<'a> {
    pub(crate) fn new(
        program: &'a Program<'a>,
        function: Function,
        local: RangeInclusive<u32>,
        control_flow: ControlFlow,
    ) -> Self {
        Self {
            program,
            function,
            local,
            control_flow,
            text: String::new(),
            depth: 0,
            missing: BTreeMap::new(),
            block: function.addr,
            sites: Vec::new(),
            taken: 0,
        }
    }

    /// Starts the block at `start`, whose code is about to write `sites`.
    pub(crate) fn begin_block(&mut self, start: u32, sites: Vec<Site>) {
        self.block = start;
        self.sites = sites;
        self.taken = 0;
    }

    /// Ends the block, checking that its code wrote every one of its sites.
    pub(crate) fn end_block(&mut self) {
        // The list and the code are two readings of the same block, and the structuring of the
        // function trusts the list: a difference is a bug of code generation, not of the guest.
        assert!(
            self.taken == self.sites.len(),
            "{}: block {:#010x}: the code wrote {} of its sites {:?}",
            function_name(self.function.addr),
            self.block,
            self.taken,
            self.sites,
        );
    }

    /// Takes the next site of the block, which has to be a transfer of `kind` to `target`, and
    /// returns the statements that make it. With a dispatcher they are `pc = target;`, and
    /// `continue;` after it for a hook, whose jump leaves the middle of the block. In structured
    /// code the site is a placeholder line, which the walk of the structured form replaces; it says
    /// whether more code of the block follows it, `followed`.
    pub(crate) fn goto(&mut self, kind: SiteKind, target: u32, followed: bool) -> Vec<String> {
        self.take(Site { kind, target });
        if self.control_flow == ControlFlow::Structured {
            return vec![placeholder(self.taken - 1, followed)];
        }
        let mut statements = vec![format!("pc = {target:#010x};")];
        if kind == SiteKind::Hook {
            statements.push("continue;".to_owned());
        }
        statements
    }

    /// Takes the sites of the resolved jump table that ends the block, one for each distinct
    /// address of `targets`, and writes the code that goes to the block CTR holds: with a
    /// dispatcher, `pc = ctx.ctr as u32;`, whose last arm catches a value that is no block; in
    /// structured code, a `match` with an arm for each site, whose last arm panics.
    pub(crate) fn table(&mut self, targets: &[u32]) {
        let distinct: BTreeSet<u32> = targets.iter().copied().collect();
        if self.control_flow == ControlFlow::Dispatch {
            for target in distinct {
                self.take(Site {
                    kind: SiteKind::Table,
                    target,
                });
            }
            self.line("pc = ctx.ctr as u32;");
            return;
        }
        self.open("match ctx.ctr as u32 {");
        for target in distinct {
            self.take(Site {
                kind: SiteKind::Table,
                target,
            });
            self.open(format!("{target:#010x} => {{"));
            self.line(placeholder(self.taken - 1, false));
            self.close("}");
        }
        self.line(format!(
            "_ => ferrum_runtime::no_block(\"{}\", ctx.ctr as u32),",
            function_name(self.function.addr)
        ));
        self.close("}");
    }

    /// The text written so far, which it leaves empty.
    pub(crate) fn take_text(&mut self) -> String {
        std::mem::take(&mut self.text)
    }

    /// Adds a line at `depth`, whatever the current depth.
    pub(crate) fn line_at(&mut self, depth: usize, line: &str) {
        let current = std::mem::replace(&mut self.depth, depth);
        self.line(line);
        self.depth = current;
    }

    /// Takes the next site of the block, checking that it is `site`.
    fn take(&mut self, site: Site) {
        let next = self.sites.get(self.taken).copied();
        // As in `end_block`: the code and the list have to agree.
        assert!(
            next == Some(site),
            "{}: block {:#010x}: the code writes {site:?} where the next site is {next:?}",
            function_name(self.function.addr),
            self.block,
        );
        self.taken += 1;
    }

    /// Adds a line at the current depth.
    pub(crate) fn line(&mut self, line: impl AsRef<str>) {
        let line = line.as_ref();
        if !line.is_empty() {
            for _ in 0..self.depth {
                self.text.push_str("    ");
            }
            self.text.push_str(line);
        }
        self.text.push('\n');
    }

    /// Adds a line that opens a block, and goes one level deeper.
    pub(crate) fn open(&mut self, line: impl AsRef<str>) {
        self.line(line);
        self.depth += 1;
    }

    /// Goes one level up, and adds the line that closes the block.
    pub(crate) fn close(&mut self, line: impl AsRef<str>) {
        self.depth -= 1;
        self.line(line);
    }

    /// Adds a line one level up that closes a block and opens the next, as `} else {`.
    pub(crate) fn reopen(&mut self, line: impl AsRef<str>) {
        self.depth -= 1;
        self.line(line);
        self.depth += 1;
    }

    /// Counts an instruction that has no `emit_*`.
    pub(crate) fn missing(&mut self, name: impl Into<String>) {
        *self.missing.entry(name.into()).or_insert(0) += 1;
    }

    /// The text of the function, or the opcodes it lacks.
    pub(crate) fn finish(self) -> Result<String, Error> {
        if self.missing.is_empty() {
            Ok(self.text)
        } else {
            Err(Error::MissingEmit {
                counts: self.missing,
            })
        }
    }

    /// `rT = value`.
    fn set(&mut self, rt: Gpr, value: impl AsRef<str>) {
        self.line(format!("ctx.r[{}] = {};", rt.0, value.as_ref()));
    }

    /// CR0 from the result in `rt`, as a record form (Rc=1) sets it in 32-bit mode: the low word,
    /// compared with zero as a signed number, and SO.
    fn record(&mut self, rt: Gpr) {
        self.line(format!(
            "ctx.cr.set_compare(0, ctx.r[{}] as i32, 0, ctx.xer.so);",
            rt.0
        ));
    }

    /// `rT = value`, then CR0 if `rc`.
    fn set_rc(&mut self, rt: Gpr, value: impl AsRef<str>, rc: bool) {
        self.set(rt, value);
        if rc {
            self.record(rt);
        }
    }

    /// `frT = value`, then CR1 if `rc`.
    fn set_f(&mut self, frt: Fpr, value: impl AsRef<str>, rc: bool) {
        self.line(format!("ctx.f[{}] = {};", frt.0, value.as_ref()));
        self.record_f(rc);
    }

    /// If `rc`, CR1 as a floating-point record form (Rc=1) sets it: FPSCR bits 0:3, after the
    /// operation.
    fn record_f(&mut self, rc: bool) {
        if rc {
            self.line("ctx.cr.set_field(1, ctx.fpscr.record());");
        }
    }
}

/// Emits one instruction that is not a branch.
pub(crate) fn emit(e: &mut Emitter<'_>, at: u32, insn: &Insn) -> Result<(), Error> {
    let known = integer::emit(e, at, insn)?
        || rotate::emit(e, insn)?
        || memory::emit(e, at, insn)?
        || float::emit(e, at, insn)?
        || vector::emit(e, insn)
        || system::emit(e, at, insn)?;
    if !known {
        e.missing(insn.opcode().info().mnemonic);
    }
    Ok(())
}

/// The whole register `r`.
fn r(r: Gpr) -> String {
    format!("ctx.r[{}]", r.0)
}

/// The low word of register `r`.
fn w(r: Gpr) -> String {
    format!("(ctx.r[{}] as u32)", r.0)
}

/// A 64-bit constant, from its signed value.
fn imm(value: i64) -> String {
    // The bits of the two's complement are the constant.
    format!("{:#x}", value as u64)
}

/// `base + value`, where `value` is a signed constant and the sum wraps.
fn plus(base: &str, value: i64) -> String {
    match value {
        0 => base.to_owned(),
        v if v < 0 => format!("{base}.wrapping_sub({:#x})", v.unsigned_abs()),
        v => format!("{base}.wrapping_add({v:#x})"),
    }
}
