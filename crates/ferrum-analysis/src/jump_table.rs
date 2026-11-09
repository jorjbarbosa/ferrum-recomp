// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Jump tables: the `bctr` that ends a `switch`.
//!
//! The instructions before a `bctr` are evaluated on symbolic register values, to tell whether CTR
//! comes from an entry of a table at a constant address, read at an index that something limits:
//! a bound check on that straight run, or the interval that the analysis of the function's blocks
//! gives the index at the load (`ranges`), whichever is tighter.

use std::collections::{BTreeMap, BTreeSet};

use ferrum_decoder::{Insn, decode};

use crate::code::Code;
use crate::flow::{Flow, flow, links};
use crate::ranges::{Range, Ranges};
use crate::regs::gpr_writes;

/// How many instructions before a `bctr` the evaluation looks at, at most.
const RUN: usize = 32;

/// The most entries a table may have. An interval that allows more, such as the `[0, mask]` of a
/// left shift, is taken as no bound: no `switch` of the games studied comes near, and reading
/// that many entries would only find targets outside the function.
const MAX_ENTRIES: u32 = 1 << 16;

/// The SPR number of CTR.
const CTR: u16 = 9;

/// A resolved jump table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    /// Address of the first entry of the table.
    pub table: u32,
    /// Size of an entry in bytes: 4 for a table of addresses, 1 or 2 for offsets.
    pub entry_size: u8,
    /// The address each index branches to, in index order.
    pub targets: Vec<u32>,
}

/// What a `bctr` turns out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Detection {
    /// CTR comes from a table whose index is bounded.
    Table(JumpTable),
    /// CTR comes from a table, but nothing bounds the index, or the table is not in the code.
    Unresolved,
    /// CTR does not come from a table: an indirect branch, such as a virtual call.
    Indirect,
}

/// A read of a table entry, shifted left by `shift`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Load {
    table: u32,
    size: u8,
    index: u32,
    shift: u8,
    /// The address of the indexed load.
    at: u32,
    /// The GPR that holds the index, scaled by the size of an entry, at the load.
    reg: u8,
}

/// What the evaluation knows about a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    /// An unknown value, shifted left by `shift`. Two registers with the same `id` hold the same
    /// unknown.
    Unknown { id: u32, shift: u8 },
    /// A constant.
    Const(u32),
    /// A table entry.
    Entry(Load),
    /// A constant plus a table entry.
    Sum { base: u32, load: Load },
}

/// The symbolic state of the registers along the run.
struct State {
    gpr: [Value; 32],
    ctr: Value,
    /// For each CR field, the unknown and the immediate of the compare that last set it.
    cr: [Option<(u32, u32)>; 8],
    /// The number of table entries a bound check allows, by unknown.
    bounds: BTreeMap<u32, u32>,
    next: u32,
}

impl State {
    fn new() -> Self {
        let gpr = std::array::from_fn(|reg| Value::Unknown {
            id: reg as u32,
            shift: 0,
        });
        Self {
            gpr,
            ctr: Value::Unknown { id: 32, shift: 0 },
            cr: [None; 8],
            bounds: BTreeMap::new(),
            next: 33,
        }
    }

    /// Forgets everything: another path joins here, with values of its own.
    fn forget(&mut self) {
        for reg in 0..32 {
            self.gpr[reg] = self.fresh();
        }
        self.ctr = self.fresh();
        self.cr = [None; 8];
    }

    fn fresh(&mut self) -> Value {
        self.next += 1;
        Value::Unknown {
            id: self.next,
            shift: 0,
        }
    }

    /// The value of `ra` as a base register, where r0 reads as zero.
    fn base(&self, ra: u8) -> Value {
        if ra == 0 {
            Value::Const(0)
        } else {
            self.gpr[usize::from(ra)]
        }
    }

    fn step(&mut self, insn: &Insn, addr: u32) {
        if links(insn) {
            // A call may change any register.
            self.forget();
            return;
        }
        if let Flow::Jump {
            conditional: true, ..
        } = flow(insn, addr)
        {
            self.bound(insn);
            return;
        }
        let (dest, value) = match *insn {
            Insn::Addi { rt, ra, si } => (rt.0, self.add_const(ra.0, si as i32 as u32)),
            Insn::Addis { rt, ra, si } => (rt.0, self.add_const(ra.0, (si as i32 as u32) << 16)),
            Insn::Ori { ra, rs, ui } | Insn::Oris { ra, rs, ui } if ui == 0 => {
                (ra.0, self.gpr[usize::from(rs.0)])
            }
            Insn::Ori { ra, rs, ui } => (ra.0, self.or_const(rs.0, u32::from(ui))),
            Insn::Oris { ra, rs, ui } => (ra.0, self.or_const(rs.0, u32::from(ui) << 16)),
            Insn::Or { ra, rs, rb, .. } if rs == rb => (ra.0, self.gpr[usize::from(rs.0)]),
            Insn::Rlwinm {
                ra, rs, sh, mb, me, ..
            } => (ra.0, self.rotate(rs.0, sh, mb, me)),
            Insn::Add { rt, ra, rb, .. } => (rt.0, self.add(ra.0, rb.0)),
            Insn::Lwzx { rt, ra, rb } => (rt.0, self.load(ra.0, rb.0, 4, addr)),
            Insn::Lhzx { rt, ra, rb } => (rt.0, self.load(ra.0, rb.0, 2, addr)),
            Insn::Lbzx { rt, ra, rb } => (rt.0, self.load(ra.0, rb.0, 1, addr)),
            Insn::Mtspr { spr: CTR, rs } => {
                self.ctr = self.gpr[usize::from(rs.0)];
                return;
            }
            Insn::Cmpli {
                bf,
                l: false,
                ra,
                ui,
                ..
            } => {
                self.compare(bf.0, ra.0, Some(u32::from(ui)));
                return;
            }
            Insn::Cmpi {
                bf,
                l: false,
                ra,
                si,
                ..
            } => {
                self.compare(bf.0, ra.0, u32::try_from(si).ok());
                return;
            }
            Insn::Cmpli { bf, .. }
            | Insn::Cmpi { bf, .. }
            | Insn::Cmp { bf, .. }
            | Insn::Cmpl { bf, .. }
            | Insn::Fcmpu { bf, .. }
            | Insn::Fcmpo { bf, .. } => {
                self.cr[usize::from(bf.0)] = None;
                return;
            }
            _ => {
                let writes = gpr_writes(insn);
                for reg in 0..32u8 {
                    if writes.contains(reg) {
                        self.gpr[usize::from(reg)] = self.fresh();
                    }
                }
                return;
            }
        };
        self.gpr[usize::from(dest)] = value;
    }

    fn add_const(&mut self, ra: u8, imm: u32) -> Value {
        match self.base(ra) {
            Value::Const(c) => Value::Const(c.wrapping_add(imm)),
            _ => self.fresh(),
        }
    }

    fn or_const(&mut self, rs: u8, imm: u32) -> Value {
        match self.gpr[usize::from(rs)] {
            Value::Const(c) => Value::Const(c | imm),
            _ => self.fresh(),
        }
    }

    /// `rlwinm`: a left shift of anything the evaluation tracks, or any rotate of a constant.
    fn rotate(&mut self, rs: u8, sh: u8, mb: u8, me: u8) -> Value {
        let value = self.gpr[usize::from(rs)];
        if let Value::Const(c) = value {
            return Value::Const(c.rotate_left(u32::from(sh)) & mask32(mb, me));
        }
        if mb != 0 || u32::from(me) + u32::from(sh) != 31 {
            return self.fresh();
        }
        match value {
            Value::Unknown { id, shift } if shift + sh < 32 => Value::Unknown {
                id,
                shift: shift + sh,
            },
            Value::Entry(load) if load.shift + sh < 32 => Value::Entry(Load {
                shift: load.shift + sh,
                ..load
            }),
            _ => self.fresh(),
        }
    }

    fn add(&mut self, ra: u8, rb: u8) -> Value {
        match (self.gpr[usize::from(ra)], self.gpr[usize::from(rb)]) {
            (Value::Const(a), Value::Const(b)) => Value::Const(a.wrapping_add(b)),
            (Value::Const(base), Value::Entry(load)) | (Value::Entry(load), Value::Const(base)) => {
                Value::Sum { base, load }
            }
            _ => self.fresh(),
        }
    }

    /// An indexed load of `size` bytes at `at`: a table entry when one operand is a constant and
    /// the other an unknown scaled by the size.
    fn load(&mut self, ra: u8, rb: u8, size: u8, at: u32) -> Value {
        let scale = size.trailing_zeros() as u8;
        let entry = |table: Value, index: Value, reg: u8| match (table, index) {
            (Value::Const(table), Value::Unknown { id, shift }) if shift == scale => {
                Some(Value::Entry(Load {
                    table,
                    size,
                    index: id,
                    shift: 0,
                    at,
                    reg,
                }))
            }
            _ => None,
        };
        let (a, b) = (self.base(ra), self.gpr[usize::from(rb)]);
        entry(a, b, rb)
            .or_else(|| (ra != 0).then(|| entry(b, a, ra)).flatten())
            .unwrap_or_else(|| self.fresh())
    }

    fn compare(&mut self, field: u8, ra: u8, imm: Option<u32>) {
        self.cr[usize::from(field)] = match (self.gpr[usize::from(ra)], imm) {
            (Value::Unknown { id, shift: 0 }, Some(imm)) => Some((id, imm)),
            _ => None,
        };
    }

    /// A conditional branch or return that leaves the run when its CR field says greater, or not
    /// less, bounds the unknown of the compare that set the field.
    fn bound(&mut self, insn: &Insn) {
        let (bo, bi) = match *insn {
            Insn::Bc { bo, bi, .. } | Insn::Bclr { bo, bi, .. } => (bo, bi.0),
            _ => return,
        };
        let Some((id, imm)) = self.cr[usize::from(bi / 4)] else {
            return;
        };
        let entries = match (bo & 0x1C, bi % 4) {
            // Branch if GT is set: the run goes on with index <= imm.
            (0x0C, 1) => imm.checked_add(1),
            // Branch if LT is clear: the run goes on with index < imm.
            (0x04, 0) => Some(imm),
            _ => None,
        };
        if let Some(entries) = entries {
            let bound = self.bounds.entry(id).or_insert(entries);
            *bound = (*bound).min(entries);
        }
    }
}

/// MASK(mb + 32, me + 32) of the ISA, on the low word.
pub(crate) fn mask32(mb: u8, me: u8) -> u32 {
    let from_mb = u32::MAX >> mb;
    let to_me = u32::MAX << (31 - me);
    if mb <= me {
        from_mb & to_me
    } else {
        from_mb | to_me
    }
}

/// The straight run of instructions before `bctr`: back to the instruction after the last
/// unconditional branch, at most [`RUN`] of them, and never before `floor`.
fn run(code: &Code<'_>, floor: u32, bctr: u32) -> Vec<(u32, Insn)> {
    let mut run = Vec::new();
    let mut addr = bctr;
    while run.len() < RUN && addr >= floor.saturating_add(4) {
        addr -= 4;
        let Some(insn) = code.word(addr).and_then(decode) else {
            break;
        };
        if let Flow::Jump {
            conditional: false, ..
        } = flow(&insn, addr)
        {
            break;
        }
        run.push((addr, insn));
    }
    run.reverse();
    run
}

/// Reads entry `index` of `load`'s table and shifts it.
fn read(code: &Code<'_>, load: &Load, index: u32) -> Option<u32> {
    let addr = load
        .table
        .checked_add(index.checked_mul(u32::from(load.size))?)?;
    let bytes = code.bytes(addr, usize::from(load.size))?;
    let value = bytes
        .iter()
        .fold(0u32, |value, &byte| value << 8 | u32::from(byte));
    Some(value << load.shift)
}

/// Works out what the `bctr` at `bctr` is, looking no further back than `floor`. `joins` are the
/// addresses that branches of the function target: another path enters there, so the evaluation
/// forgets what it knew. The count of entries is the tighter of the bound check of the straight
/// run and of the interval `ranges` gives the index at the load; `entries`, from
/// `[analysis] jump_tables`, replaces both.
pub(crate) fn detect(
    code: &Code<'_>,
    floor: u32,
    bctr: u32,
    joins: &BTreeSet<u32>,
    entries: Option<u32>,
    ranges: Option<&Ranges<'_>>,
) -> Detection {
    let mut state = State::new();
    for (index, (addr, insn)) in run(code, floor, bctr).into_iter().enumerate() {
        if index > 0 && joins.contains(&addr) {
            state.forget();
        }
        state.step(&insn, addr);
    }
    let (base, load) = match state.ctr {
        Value::Entry(load) => (0, load),
        Value::Sum { base, load } => (base, load),
        _ => return Detection::Indirect,
    };
    let checked = state.bounds.get(&load.index).copied();
    let ranged = ranges.and_then(|ranges| match ranges.before(load.at, load.reg) {
        // The GPR holds the index scaled by the size of an entry.
        Range::Span(_, hi) => (hi >> load.size.trailing_zeros()).checked_add(1),
        Range::Unknown => None,
    });
    let bound = match (checked, ranged) {
        (Some(checked), Some(ranged)) => Some(checked.min(ranged)),
        (checked, ranged) => checked.or(ranged),
    };
    let Some(count) = entries.or(bound.filter(|&count| count <= MAX_ENTRIES)) else {
        return Detection::Unresolved;
    };
    let targets: Option<Vec<u32>> = (0..count)
        .map(|index| read(code, &load, index).map(|entry| base.wrapping_add(entry)))
        .collect();
    match targets {
        Some(targets) => Detection::Table(JumpTable {
            table: load.table,
            entry_size: load.size,
            targets,
        }),
        None => Detection::Unresolved,
    }
}

#[cfg(test)]
mod tests;
