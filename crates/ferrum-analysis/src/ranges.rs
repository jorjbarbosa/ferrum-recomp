// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Unsigned intervals of the GPRs over the blocks of a function.
//!
//! The index of a `switch` is often bounded far from its `bctr`: in an earlier block on every
//! path, by a mask, by the check of an earlier `switch` on the same index, or by the constants
//! each path of a state machine stores. A forward analysis over the blocks carries what each path
//! knows about every GPR, as an interval, and joins the paths where they meet.
//!
//! What it knows comes from constants, `addi`, masks, byte and halfword loads, copies, and the
//! two edges of a conditional branch after a compare with an immediate. Whatever else writes a
//! GPR makes it unknown; a call keeps the registers the ABI preserves. The analysis is
//! conservative: what it leaves out costs precision, never an interval that a path could leave.

use std::collections::{BTreeMap, BTreeSet};

use ferrum_decoder::Insn;

use crate::cfg::{Block, Exit, Function};
use crate::flow::{Flow, Target, flow, links};
use crate::jump_table::mask32;
use crate::regs::gpr_writes;

#[cfg(test)]
mod tests;

/// What the analysis knows about a GPR: unknown, or an unsigned interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Range {
    /// Any value.
    Unknown,
    /// A value from the first bound to the second, both included, the first no greater.
    Span(u32, u32),
}

impl Range {
    /// The interval `[lo, hi]`, which is unknown when it holds every value.
    fn span(lo: u32, hi: u32) -> Self {
        if lo == 0 && hi == u32::MAX {
            Range::Unknown
        } else {
            Range::Span(lo, hi)
        }
    }

    fn bounds(self) -> (u32, u32) {
        match self {
            Range::Unknown => (0, u32::MAX),
            Range::Span(lo, hi) => (lo, hi),
        }
    }

    /// The smallest interval that holds both.
    fn join(self, other: Self) -> Self {
        let (a, b) = (self.bounds(), other.bounds());
        Range::span(a.0.min(b.0), a.1.max(b.1))
    }

    /// The interval plus `delta`, or unknown if some value would wrap past 0 or 2^32.
    fn add(self, delta: i64) -> Self {
        let Range::Span(lo, hi) = self else {
            return Range::Unknown;
        };
        let lo = i64::from(lo) + delta;
        let hi = i64::from(hi) + delta;
        match (u32::try_from(lo), u32::try_from(hi)) {
            (Ok(lo), Ok(hi)) => Range::span(lo, hi),
            _ => Range::Unknown,
        }
    }
}

/// How a compare relates a GPR to its immediate on one edge of a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Lt,
    Ge,
    Gt,
    Le,
    Eq,
    Ne,
}

/// The interval of a GPR that holds `relation` with `imm`, or `None` if no value of `range` does.
fn narrow(range: Range, relation: Relation, imm: u32) -> Option<Range> {
    let (lo, hi) = range.bounds();
    let (lo, hi) = match relation {
        Relation::Lt => (lo, hi.min(imm.checked_sub(1)?)),
        Relation::Le => (lo, hi.min(imm)),
        Relation::Gt => (lo.max(imm.checked_add(1)?), hi),
        Relation::Ge => (lo.max(imm), hi),
        Relation::Eq => (lo.max(imm), hi.min(imm)),
        Relation::Ne if lo == imm && hi == imm => return None,
        Relation::Ne if lo == imm => (lo + 1, hi),
        Relation::Ne if hi == imm => (lo, hi - 1),
        Relation::Ne => (lo, hi),
    };
    (lo <= hi).then(|| Range::span(lo, hi))
}

/// What the analysis knows at one point: the GPRs, and for each CR field the GPR and the
/// immediate of the compare that set it, while neither has changed since.
#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    gpr: [Range; 32],
    cr: [Option<(u8, u32)>; 8],
}

impl State {
    fn unknown() -> Self {
        Self {
            gpr: [Range::Unknown; 32],
            cr: [None; 8],
        }
    }

    /// The state that holds both: the union of each GPR, and the compares both agree on.
    fn join(&self, other: &Self) -> Self {
        Self {
            gpr: std::array::from_fn(|reg| self.gpr[reg].join(other.gpr[reg])),
            cr: std::array::from_fn(|field| {
                (self.cr[field] == other.cr[field])
                    .then_some(self.cr[field])
                    .flatten()
            }),
        }
    }

    /// The value of `ra` as a base or source of `addi`, where r0 reads as zero.
    fn base(&self, ra: u8) -> Range {
        if ra == 0 {
            Range::Span(0, 0)
        } else {
            self.gpr[usize::from(ra)]
        }
    }

    fn step(&mut self, insn: &Insn) {
        if links(insn) {
            // The ABI preserves r1, r2 and r13 to r31 across a call, and no CR field it uses here.
            self.gpr[0] = Range::Unknown;
            for reg in 3..=12 {
                self.gpr[reg] = Range::Unknown;
            }
            self.cr = [None; 8];
            return;
        }
        match *insn {
            Insn::Cmpli {
                bf,
                l: false,
                ra,
                ui,
                ..
            } => {
                self.cr[usize::from(bf.0)] = Some((ra.0, u32::from(ui)));
                return;
            }
            // A signed compare with a non-negative immediate counts as an unsigned one. A
            // negative value passes it, so this trusts the code to keep the value non-negative;
            // a table read too far for one mostly has a target outside its function, which
            // leaves it unresolved.
            Insn::Cmpi {
                bf,
                l: false,
                ra,
                si,
                ..
            } => {
                self.cr[usize::from(bf.0)] = u32::try_from(si).ok().map(|imm| (ra.0, imm));
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
            _ => {}
        }
        if !keeps_cr(insn) {
            self.cr = [None; 8];
        }
        let value = self.value(insn);
        let writes = gpr_writes(insn);
        for reg in 0..32u8 {
            if writes.contains(reg) {
                self.gpr[usize::from(reg)] = Range::Unknown;
                for field in &mut self.cr {
                    if matches!(*field, Some((compared, _)) if compared == reg) {
                        *field = None;
                    }
                }
            }
        }
        if let Some((reg, range)) = value {
            self.gpr[usize::from(reg)] = range;
        }
    }

    /// The GPR an instruction writes and its interval, for the instructions the analysis
    /// follows, from the state before the instruction.
    fn value(&self, insn: &Insn) -> Option<(u8, Range)> {
        let gpr = |reg: ferrum_decoder::Gpr| self.gpr[usize::from(reg.0)];
        Some(match *insn {
            Insn::Addi { rt, ra, si } => (rt.0, self.base(ra.0).add(i64::from(si))),
            Insn::Addis { rt, ra, si } => (rt.0, self.base(ra.0).add(i64::from(si) << 16)),
            Insn::Ori { ra, rs, ui: 0 } | Insn::Oris { ra, rs, ui: 0 } => (ra.0, gpr(rs)),
            Insn::Ori { ra, rs, ui } => (ra.0, or_const(gpr(rs), u32::from(ui))),
            Insn::Oris { ra, rs, ui } => (ra.0, or_const(gpr(rs), u32::from(ui) << 16)),
            Insn::Or { ra, rs, rb, .. } if rs == rb => (ra.0, gpr(rs)),
            Insn::Rlwinm {
                ra, rs, sh, mb, me, ..
            } => (ra.0, rotate(gpr(rs), sh, mb, me)),
            Insn::AndiDot { ra, ui, .. } => (ra.0, Range::span(0, u32::from(ui))),
            Insn::AndisDot { ra, ui, .. } => (ra.0, Range::span(0, u32::from(ui) << 16)),
            Insn::Lbz { rt, .. } | Insn::Lbzx { rt, .. } | Insn::Lbzu { rt, .. } => {
                (rt.0, Range::Span(0, 0xFF))
            }
            Insn::Lhz { rt, .. } | Insn::Lhzx { rt, .. } => (rt.0, Range::Span(0, 0xFFFF)),
            _ => return None,
        })
    }
}

/// `x | imm` for a constant `x`; unknown otherwise.
fn or_const(range: Range, imm: u32) -> Range {
    match range {
        Range::Span(lo, hi) if lo == hi => Range::Span(lo | imm, lo | imm),
        _ => Range::Unknown,
    }
}

/// `rlwinm`: exact for a constant, a left shift that does not overflow and a right shift; within
/// the mask otherwise, since the result has no bit outside it.
fn rotate(range: Range, sh: u8, mb: u8, me: u8) -> Range {
    let mask = mask32(mb, me);
    if let Range::Span(lo, hi) = range {
        if lo == hi {
            let value = lo.rotate_left(u32::from(sh)) & mask;
            return Range::Span(value, value);
        }
        // slwi: a left shift by sh.
        if mb == 0 && u32::from(me) + u32::from(sh) == 31 && hi <= u32::MAX >> sh {
            return Range::span(lo << sh, hi << sh);
        }
        // srwi: a right shift by mb, as a rotate left by 32 - mb.
        if me == 31 && mb > 0 && u32::from(sh) + u32::from(mb) == 32 {
            return Range::span(lo >> mb, hi >> mb);
        }
    }
    Range::span(0, mask)
}

/// Returns whether `insn` leaves every CR field as it was. The list holds the instructions that
/// a compare and its branch may have between them; any other instruction is taken to change CR,
/// which only costs a bound.
fn keeps_cr(insn: &Insn) -> bool {
    matches!(
        *insn,
        Insn::Lwz { .. }
            | Insn::Lwzx { .. }
            | Insn::Lwzu { .. }
            | Insn::Lbz { .. }
            | Insn::Lbzx { .. }
            | Insn::Lbzu { .. }
            | Insn::Lhz { .. }
            | Insn::Lhzx { .. }
            | Insn::Lha { .. }
            | Insn::Lhax { .. }
            | Insn::Ld { .. }
            | Insn::Ldx { .. }
            | Insn::Ldu { .. }
            | Insn::Lfs { .. }
            | Insn::Lfsx { .. }
            | Insn::Lfd { .. }
            | Insn::Lfdx { .. }
            | Insn::Stw { .. }
            | Insn::Stwx { .. }
            | Insn::Stwu { .. }
            | Insn::Stb { .. }
            | Insn::Stbx { .. }
            | Insn::Sth { .. }
            | Insn::Sthx { .. }
            | Insn::Std { .. }
            | Insn::Stdx { .. }
            | Insn::Stdu { .. }
            | Insn::Stfs { .. }
            | Insn::Stfd { .. }
            | Insn::Addi { .. }
            | Insn::Addis { .. }
            | Insn::Ori { .. }
            | Insn::Oris { .. }
            | Insn::Xori { .. }
            | Insn::Xoris { .. }
            | Insn::Mulli { .. }
            | Insn::Rlwinm { rc: false, .. }
            | Insn::Rlwimi { rc: false, .. }
            | Insn::Or { rc: false, .. }
            | Insn::And { rc: false, .. }
            | Insn::Andc { rc: false, .. }
            | Insn::Add { rc: false, .. }
            | Insn::Subf { rc: false, .. }
            | Insn::Mullw { rc: false, .. }
            | Insn::Neg { rc: false, .. }
            | Insn::Extsb { rc: false, .. }
            | Insn::Extsh { rc: false, .. }
            | Insn::Extsw { rc: false, .. }
            | Insn::Mfspr { .. }
            | Insn::Mtspr { .. }
            | Insn::B { .. }
            | Insn::Bc { .. }
            | Insn::Bclr { .. }
            | Insn::Bcctr { .. }
    )
}

/// Which edge of a block's last instruction a successor is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edge {
    /// An edge that tells nothing: an unconditional branch, a table target, or the fallthrough
    /// of an instruction that is no branch.
    Plain,
    /// The target of a conditional branch.
    Taken,
    /// The fallthrough of a conditional branch, return or `bcctr`.
    NotTaken,
}

/// The successors of `block` inside `function`: its fallthrough, its branch target, and the
/// targets of its table in `tables`.
fn successors(
    block: &Block,
    function: Function,
    tables: &BTreeMap<u32, Vec<u32>>,
) -> Vec<(u32, Edge)> {
    let mut next = Vec::new();
    let Some(&(addr, insn)) = block.insns.last() else {
        return next;
    };
    let branch = flow(&insn, addr);
    let conditional = matches!(
        branch,
        Flow::Jump {
            conditional: true,
            ..
        }
    );
    if let Exit::Next(to) = block.exit {
        next.push((
            to,
            if conditional {
                Edge::NotTaken
            } else {
                Edge::Plain
            },
        ));
    }
    match branch {
        Flow::Jump {
            target: Target::Address(to),
            conditional,
        } if function.contains(to) => {
            next.push((
                to,
                if conditional {
                    Edge::Taken
                } else {
                    Edge::Plain
                },
            ));
        }
        Flow::Jump {
            target: Target::Ctr,
            conditional: false,
        } => {
            for &to in tables.get(&addr).into_iter().flatten() {
                next.push((to, Edge::Plain));
            }
        }
        _ => {}
    }
    next
}

/// The state on one edge out of a block whose last instruction is `insn`, narrowed by its
/// condition, or `None` if no value can take the edge.
fn along(mut state: State, insn: &Insn, edge: Edge) -> Option<State> {
    let taken = match edge {
        Edge::Plain => return Some(state),
        Edge::Taken => true,
        Edge::NotTaken => false,
    };
    let (bo, bi) = match *insn {
        Insn::Bc { bo, bi, .. } | Insn::Bclr { bo, bi, .. } | Insn::Bcctr { bo, bi, .. } => {
            (bo, bi.0)
        }
        _ => return Some(state),
    };
    // BO: 0x10 ignores the CR bit; without 0x04 the branch also decrements CTR and tests it,
    // so its not-taken edge tells nothing of the bit. 0x08 is the value of the bit that branches.
    if bo & 0x10 != 0 || bo & 0x04 == 0 {
        return Some(state);
    }
    let Some((reg, imm)) = state.cr[usize::from(bi / 4)] else {
        return Some(state);
    };
    let set = taken == (bo & 0x08 != 0);
    let relation = match (bi % 4, set) {
        (0, true) => Relation::Lt,
        (0, false) => Relation::Ge,
        (1, true) => Relation::Gt,
        (1, false) => Relation::Le,
        (2, true) => Relation::Eq,
        (2, false) => Relation::Ne,
        _ => return Some(state),
    };
    let reg = usize::from(reg);
    state.gpr[reg] = narrow(state.gpr[reg], relation, imm)?;
    Some(state)
}

/// How many times the interval of a GPR at a block start may change before it becomes unknown.
const WIDEN_AFTER: u8 = 8;

/// The intervals of the GPRs at the start of every block that a path reaches.
#[derive(Debug)]
pub(crate) struct Ranges<'b> {
    blocks: &'b [Block],
    /// The index in `blocks` of each block, by its start.
    index: BTreeMap<u32, usize>,
    entry: BTreeMap<u32, State>,
}

/// Runs the analysis over `blocks`, the blocks of `function` in address order, with the targets
/// of the tables decided so far in `tables` and the addresses that control reaches from outside
/// in `externals`.
pub(crate) fn analyze<'b>(
    function: Function,
    blocks: &'b [Block],
    tables: &BTreeMap<u32, Vec<u32>>,
    externals: &BTreeSet<u32>,
) -> Ranges<'b> {
    let index: BTreeMap<u32, usize> = blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut entry = BTreeMap::new();
    let mut pending = BTreeSet::new();
    for start in std::iter::once(function.addr).chain(externals.iter().copied()) {
        if index.contains_key(&start) {
            entry.insert(start, State::unknown());
            pending.insert(start);
        }
    }
    let mut changes: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
    while let Some(start) = pending.pop_first() {
        let block = &blocks[index[&start]];
        let mut state = entry[&start].clone();
        for (_, insn) in &block.insns {
            state.step(insn);
        }
        let Some(&(_, last)) = block.insns.last() else {
            continue;
        };
        for (to, edge) in successors(block, function, tables) {
            if !index.contains_key(&to) {
                continue;
            }
            let Some(out) = along(state.clone(), &last, edge) else {
                continue;
            };
            let mut merged = match entry.get(&to) {
                Some(old) => old.join(&out),
                None => out,
            };
            if let Some(old) = entry.get(&to) {
                if *old == merged {
                    continue;
                }
                let counts = changes.entry(to).or_insert([0; 32]);
                for ((count, new), was) in counts.iter_mut().zip(&mut merged.gpr).zip(&old.gpr) {
                    if new != was {
                        *count = count.saturating_add(1);
                        if *count > WIDEN_AFTER {
                            *new = Range::Unknown;
                        }
                    }
                }
            }
            entry.insert(to, merged);
            pending.insert(to);
        }
    }
    Ranges {
        blocks,
        index,
        entry,
    }
}

impl Ranges<'_> {
    /// The interval of `reg` just before the instruction at `addr`; unknown when no path reaches
    /// it.
    pub(crate) fn before(&self, addr: u32, reg: u8) -> Range {
        let Some((start, &position)) = self.index.range(..=addr).next_back() else {
            return Range::Unknown;
        };
        let Some(state) = self.entry.get(start) else {
            return Range::Unknown;
        };
        let mut state = state.clone();
        for (at, insn) in &self.blocks[position].insns {
            if *at == addr {
                return state.gpr[usize::from(reg)];
            }
            state.step(insn);
        }
        Range::Unknown
    }
}
