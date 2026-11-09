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
//!
//! Code built without optimization keeps its locals in the stack frame and reloads them before
//! each use, so the GPR a compare checks is not the one that indexes the table: both are loads of
//! the same word. The analysis also carries the words of the frame, at a displacement from r1,
//! that a `stw` wrote and nothing changed since, and which GPRs still hold a copy of each, so that
//! a branch narrows the word and every copy together. A store through any other base, a store of
//! unknown address, a call, or a write to r1 forgets the frame: the word may have changed through
//! a pointer to it.

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

/// The values both intervals hold, or `None` if they hold none in common.
fn intersect(a: Range, b: Range) -> Option<Range> {
    let (a, b) = (a.bounds(), b.bounds());
    let (lo, hi) = (a.0.max(b.0), a.1.min(b.1));
    (lo <= hi).then(|| Range::span(lo, hi))
}

/// The stack pointer.
const SP: u8 = 1;

/// What the analysis knows at one point: the GPRs, for each CR field the GPR and the immediate
/// of the compare that set it while neither has changed since, the words of the stack frame by
/// their displacement from r1, and for each GPR the frame word it is a copy of.
#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    gpr: [Range; 32],
    cr: [Option<(u8, u32)>; 8],
    /// The interval of each frame word the analysis knows, none of them unknown.
    frame: BTreeMap<i32, Range>,
    /// The frame word each GPR equals, while neither has changed since a load or store made them
    /// equal.
    copy: [Option<i32>; 32],
}

impl State {
    fn unknown() -> Self {
        Self {
            gpr: [Range::Unknown; 32],
            cr: [None; 8],
            frame: BTreeMap::new(),
            copy: [None; 32],
        }
    }

    /// The state that holds both: the union of each GPR and frame word, and the compares and
    /// copies both agree on.
    fn join(&self, other: &Self) -> Self {
        Self {
            gpr: std::array::from_fn(|reg| self.gpr[reg].join(other.gpr[reg])),
            cr: std::array::from_fn(|field| {
                (self.cr[field] == other.cr[field])
                    .then_some(self.cr[field])
                    .flatten()
            }),
            frame: self
                .frame
                .iter()
                .filter_map(|(&disp, &range)| {
                    let joined = range.join(*other.frame.get(&disp)?);
                    (joined != Range::Unknown).then_some((disp, joined))
                })
                .collect(),
            copy: std::array::from_fn(|reg| {
                (self.copy[reg] == other.copy[reg])
                    .then_some(self.copy[reg])
                    .flatten()
            }),
        }
    }

    /// The interval of the frame word at `disp`.
    fn word(&self, disp: i32) -> Range {
        self.frame.get(&disp).copied().unwrap_or(Range::Unknown)
    }

    /// Records that the frame word at `disp` holds `range`.
    fn set_word(&mut self, disp: i32, range: Range) {
        if range == Range::Unknown {
            self.frame.remove(&disp);
        } else {
            self.frame.insert(disp, range);
        }
    }

    /// Forgets the frame words that overlap the `size` bytes at `disp`, and the copies of them.
    fn overwrite(&mut self, disp: i32, size: i32) {
        let overlaps = |word: i32| word < disp + size && disp < word + 4;
        self.frame.retain(|&word, _| !overlaps(word));
        for copy in &mut self.copy {
            if copy.is_some_and(overlaps) {
                *copy = None;
            }
        }
    }

    /// Forgets the whole frame.
    fn forget_frame(&mut self) {
        self.frame.clear();
        self.copy = [None; 32];
    }

    /// Narrows `reg` to the values in `range` and, when it is a copy of a frame word, the word and
    /// its other copies with it. `None` if they hold no value in common.
    fn restrict(&mut self, reg: u8, range: Range) -> Option<()> {
        let reg = usize::from(reg);
        self.gpr[reg] = intersect(self.gpr[reg], range)?;
        if let Some(disp) = self.copy[reg] {
            let word = intersect(self.word(disp), self.gpr[reg])?;
            self.set_word(disp, word);
            for other in 0..32 {
                if self.copy[other] == Some(disp) {
                    self.gpr[other] = intersect(self.gpr[other], word)?;
                }
            }
        }
        Some(())
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
            // The callee may write the frame through a pointer to a local.
            self.forget_frame();
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
        // The frame word a load copies into a GPR, or a GPR an `mr` copies, before the writes.
        let copied = match *insn {
            Insn::Lwz { rt, d, ra } if ra.0 == SP => Some((rt.0, Some(i32::from(d)))),
            Insn::Or { ra, rs, rb, .. } if rs == rb => Some((ra.0, self.copy[usize::from(rs.0)])),
            _ => None,
        };
        match frame_store(insn) {
            Store::Frame { disp, size } => {
                self.overwrite(disp, size);
                if let Insn::Stw { rs, .. } = *insn {
                    self.set_word(disp, self.gpr[usize::from(rs.0)]);
                    self.copy[usize::from(rs.0)] = Some(disp);
                }
            }
            Store::Elsewhere => self.forget_frame(),
            Store::None => {}
        }
        let writes = gpr_writes(insn);
        for reg in 0..32u8 {
            if writes.contains(reg) {
                self.gpr[usize::from(reg)] = Range::Unknown;
                self.copy[usize::from(reg)] = None;
                for field in &mut self.cr {
                    if matches!(*field, Some((compared, _)) if compared == reg) {
                        *field = None;
                    }
                }
            }
        }
        if writes.contains(SP) {
            // The words were relative to the old r1.
            self.forget_frame();
        }
        if let Some((reg, range)) = value {
            self.gpr[usize::from(reg)] = range;
        }
        if let Some((reg, copy)) = copied
            && reg != SP
        {
            self.copy[usize::from(reg)] = copy;
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
            Insn::Lwz { rt, d, ra } if ra.0 == SP => (rt.0, self.word(i32::from(d))),
            _ => return None,
        })
    }
}

/// What an instruction writes to memory, as far as the frame is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Store {
    /// Nothing.
    None,
    /// The `size` bytes at r1 plus `disp`, with r1 left as it is.
    Frame { disp: i32, size: i32 },
    /// Memory that may be anywhere, the frame included.
    Elsewhere,
}

/// What `insn` writes to memory. Every store and every cache instruction that changes memory
/// (`dcbz`, `dcbz128`, `dcbi`, `dcba`) counts; their mnemonics are the ones that start with `st`,
/// `dcbz`, `dcbi` or `dcba`, and `ecowx`. A store through r1 with a displacement and no update
/// writes the frame; any other writes memory that may be anywhere.
fn frame_store(insn: &Insn) -> Store {
    let sp = |ra: ferrum_decoder::Gpr| ra.0 == SP;
    match *insn {
        Insn::Stb { d, ra, .. } if sp(ra) => Store::Frame {
            disp: i32::from(d),
            size: 1,
        },
        Insn::Sth { d, ra, .. } if sp(ra) => Store::Frame {
            disp: i32::from(d),
            size: 2,
        },
        Insn::Stw { d, ra, .. } | Insn::Stfs { d, ra, .. } if sp(ra) => Store::Frame {
            disp: i32::from(d),
            size: 4,
        },
        Insn::Stfd { d, ra, .. } if sp(ra) => Store::Frame {
            disp: i32::from(d),
            size: 8,
        },
        Insn::Std { ds, ra, .. } if sp(ra) => Store::Frame {
            disp: i32::from(ds),
            size: 8,
        },
        // stmw writes rs to r31, one word each.
        Insn::Stmw { rs, d, ra } if sp(ra) => Store::Frame {
            disp: i32::from(d),
            size: 4 * (32 - i32::from(rs.0)),
        },
        _ => {
            let mnemonic = insn.opcode().info().mnemonic;
            let writes = ["st", "dcbz", "dcbi", "dcba", "ecowx"]
                .iter()
                .any(|prefix| mnemonic.starts_with(prefix));
            if writes {
                Store::Elsewhere
            } else {
                Store::None
            }
        }
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
    let narrowed = narrow(state.gpr[usize::from(reg)], relation, imm)?;
    state.restrict(reg, narrowed)?;
    Some(state)
}

/// How many times the interval of a GPR or a frame word at a block start may change before it
/// becomes unknown.
const WIDEN_AFTER: u8 = 8;

/// How many times each interval at a block start has changed.
#[derive(Debug, Default)]
struct Changes {
    gpr: [u8; 32],
    frame: BTreeMap<i32, u8>,
}

impl Changes {
    /// Counts the intervals of `new` that differ from `old`, and makes unknown those that changed
    /// too often. A frame word only shrinks the frame when it goes, so it cannot change forever.
    fn widen(&mut self, new: &mut State, old: &State) {
        for ((count, new), was) in self.gpr.iter_mut().zip(&mut new.gpr).zip(&old.gpr) {
            if new != was {
                *count = count.saturating_add(1);
                if *count > WIDEN_AFTER {
                    *new = Range::Unknown;
                }
            }
        }
        let mut widened = Vec::new();
        for (&disp, range) in &new.frame {
            if old.frame.get(&disp) != Some(range) {
                let count = self.frame.entry(disp).or_insert(0);
                *count = count.saturating_add(1);
                if *count > WIDEN_AFTER {
                    widened.push(disp);
                }
            }
        }
        for disp in widened {
            new.frame.remove(&disp);
        }
    }
}

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
    let mut changes: BTreeMap<u32, Changes> = BTreeMap::new();
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
                changes.entry(to).or_default().widen(&mut merged, old);
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
