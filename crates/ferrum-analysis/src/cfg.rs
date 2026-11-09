// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Basic blocks of one function, found by following its code from the entry.

use std::collections::{BTreeMap, BTreeSet};

use ferrum_decoder::{Insn, decode};

use crate::code::Code;
use crate::error::Error;
use crate::flow::{Flow, Target, branch_target, flow, is_unconditional, links};
use crate::jump_table::{self, Detection, JumpTable};
use crate::ranges;

#[cfg(test)]
mod tests;

/// A function as the caller names it: its entry and the size of its range in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Function {
    /// Address of the entry, the first byte of the range.
    pub addr: u32,
    /// Size of the range in bytes.
    pub size: u32,
}

impl Function {
    /// One past the last address of the range. It can be 2^32, hence `u64`.
    pub fn end(&self) -> u64 {
        u64::from(self.addr) + u64::from(self.size)
    }

    /// Returns whether the whole instruction at `addr` lies in the range.
    pub fn contains(&self, addr: u32) -> bool {
        addr >= self.addr && u64::from(addr) + 4 <= self.end()
    }
}

/// What the walk of a function needs to know besides its code, from discovery and the config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    /// Entries of the functions that never return: an unconditional call to one ends its block.
    pub no_return: BTreeSet<u32>,
    /// Entry counts of jump tables, by the address of their `bctr` (`[analysis] jump_tables`).
    pub table_entries: BTreeMap<u32, u32>,
    /// Entries of the functions that return twice, as `setjmp` does: the instruction after a call
    /// to one starts a block, where a `longjmp` resumes.
    pub returns_twice: BTreeSet<u32>,
    /// Addresses that control reaches from outside the code, such as the target of a mid-asm
    /// hook's jump: each one inside a function starts a block there and is a join.
    pub joins: BTreeSet<u32>,
}

impl Rules {
    /// Returns whether `insn` at `addr` calls a function that returns twice.
    pub fn returns_twice(&self, insn: &Insn, addr: u32) -> bool {
        links(insn)
            && matches!(
                branch_target(insn, addr),
                Some(Target::Address(to)) if self.returns_twice.contains(&to)
            )
    }

    /// Returns whether `insn` at `addr` is a call that never comes back: an unconditional call
    /// with a fixed target that never returns.
    pub fn never_returns(&self, insn: &Insn, addr: u32) -> bool {
        let always = match *insn {
            Insn::B { lk, .. } => lk,
            Insn::Bc { bo, lk, .. } => lk && is_unconditional(bo),
            _ => false,
        };
        always
            && matches!(
                branch_target(insn, addr),
                Some(Target::Address(to)) if self.no_return.contains(&to)
            )
    }
}

/// Where execution goes after the last instruction of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The last instruction always jumps away.
    Jump,
    /// Execution can go on past the last instruction, into the block at this address.
    Next(u32),
    /// Execution can go on past the last instruction, which is the last of the function. Code
    /// generation makes that path a tail call when a function starts there, and a panic otherwise:
    /// the function's boundary is suspicious.
    FallOff,
    /// The last instruction is a call to a function that never returns.
    NoReturn,
}

/// A run of instructions entered only at its first one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Address of the first instruction.
    pub start: u32,
    /// The instructions and their addresses, in order. A block ends at a branch that does not set
    /// the link register, before the start of another block, or at the end of the function.
    pub insns: Vec<(u32, Insn)>,
    /// Where execution goes after the last instruction.
    pub exit: Exit,
}

/// The basic blocks of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cfg {
    /// The function, as the caller named it.
    pub function: Function,
    /// The blocks in address order. The first one starts at the entry.
    pub blocks: Vec<Block>,
    /// The resolved jump tables, by the address of their `bctr`. Every target starts a block.
    pub tables: BTreeMap<u32, JumpTable>,
    /// The `bctr`s whose CTR comes from a table that could not be resolved: no bound check, or a
    /// target outside the function. Code generation makes them indirect tail calls.
    pub unresolved: BTreeSet<u32>,
}

impl Cfg {
    /// Returns whether some path runs past the last instruction of the function.
    pub fn falls_off(&self) -> bool {
        self.blocks.iter().any(|block| block.exit == Exit::FallOff)
    }

    /// One past the last instruction that a path reaches.
    pub fn reach(&self) -> u64 {
        self.blocks
            .iter()
            .filter_map(|block| block.insns.last())
            .map(|&(addr, _)| u64::from(addr) + 4)
            .max()
            .unwrap_or(u64::from(self.function.addr))
    }
}

/// Splits `function` into basic blocks.
///
/// A block starts at the entry, at the target of a branch or of a jump table inside the range,
/// and after a conditional branch. Only what some path from the entry reaches is decoded, so data
/// or padding after the last return does not matter, but an undecodable word on a path is an
/// error. A branch to an address outside the range, or to the link or count register, leaves the
/// function: code generation makes it a tail call or a return. A call to a function that `rules`
/// says never returns ends its path.
pub fn build(code: &Code<'_>, function: Function, rules: &Rules) -> Result<Cfg, Error> {
    if !function.addr.is_multiple_of(4) || !function.contains(function.addr) {
        return Err(Error::BadFunction {
            function: function.addr,
            size: function.size,
        });
    }
    let walk = Walk::settle(code, function, rules)?;
    let mut blocks = Vec::with_capacity(walk.leaders.len());
    for &start in &walk.leaders {
        blocks.push(walk.block(start));
    }
    Ok(Cfg {
        function,
        blocks,
        tables: walk.tables,
        unresolved: walk.unresolved,
    })
}

/// How many times the walk may run again because the jump tables changed.
const TABLE_ROUNDS: usize = 16;

/// What a `bctr` that loads CTR from a table turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decided {
    Table(JumpTable),
    Unresolved,
}

/// The instructions the paths of a function reach, and where its blocks start.
struct Walk<'r> {
    function: Function,
    rules: &'r Rules,
    insns: BTreeMap<u32, Insn>,
    leaders: BTreeSet<u32>,
    /// The entry and every address a branch or a jump table of the function targets: where paths
    /// join.
    joins: BTreeSet<u32>,
    /// The `bctr`s the paths reach that branch always and do not link.
    bctrs: BTreeSet<u32>,
    tables: BTreeMap<u32, JumpTable>,
    unresolved: BTreeSet<u32>,
    /// How many times `settle` decided the tables, the last time finding nothing new unless it ran
    /// out of rounds.
    rounds: usize,
}

impl<'r> Walk<'r> {
    /// Walks `function` until its jump tables settle. A table is decided on the paths of the walk
    /// before it, whose joins and intervals its evaluation needs, and its targets open more paths,
    /// so the walk runs again until the decisions stop changing. The joins of every walk are kept,
    /// and a table found unresolved stays so in the later rounds: more paths only widen the
    /// intervals, and a table that went back and forth would keep the walk from settling.
    fn settle(code: &Code<'_>, function: Function, rules: &'r Rules) -> Result<Self, Error> {
        let mut decided = BTreeMap::new();
        let mut walk = Self::run(code, function, rules, &decided)?;
        let mut joins = walk.joins.clone();
        let mut unresolved = BTreeSet::new();
        let mut rounds = 0;
        for _ in 0..TABLE_ROUNDS {
            rounds += 1;
            let mut next = walk.decide(code, &joins);
            for (&bctr, decision) in &mut next {
                if unresolved.contains(&bctr) {
                    *decision = Decided::Unresolved;
                } else if *decision == Decided::Unresolved {
                    unresolved.insert(bctr);
                }
            }
            if next == decided {
                break;
            }
            decided = next;
            walk = Self::run(code, function, rules, &decided)?;
            joins.extend(walk.joins.iter().copied());
        }
        walk.rounds = rounds;
        Ok(walk)
    }

    /// Decides every `bctr` the walk reached, with `joins` as the joins of the function and the
    /// intervals of the GPRs over the blocks of the walk.
    fn decide(&self, code: &Code<'_>, joins: &BTreeSet<u32>) -> BTreeMap<u32, Decided> {
        let mut decided = BTreeMap::new();
        if self.bctrs.is_empty() {
            // Most functions have no table: the intervals would answer no question.
            return decided;
        }
        let blocks: Vec<Block> = self
            .leaders
            .iter()
            .map(|&start| self.block(start))
            .collect();
        let tables: BTreeMap<u32, Vec<u32>> = self
            .tables
            .iter()
            .map(|(&bctr, table)| (bctr, table.targets.clone()))
            .collect();
        let externals: BTreeSet<u32> = self
            .rules
            .joins
            .iter()
            .copied()
            .filter(|&addr| self.function.contains(addr))
            .collect();
        let ranges = ranges::analyze(self.function, &blocks, &tables, &externals);
        for &bctr in &self.bctrs {
            let entries = self.rules.table_entries.get(&bctr).copied();
            let floor = self.function.addr;
            let decision =
                match jump_table::detect(code, floor, bctr, joins, entries, Some(&ranges)) {
                    Detection::Table(table)
                        if table
                            .targets
                            .iter()
                            .all(|&to| to.is_multiple_of(4) && self.function.contains(to)) =>
                    {
                        Decided::Table(table)
                    }
                    Detection::Table(_) | Detection::Unresolved => Decided::Unresolved,
                    Detection::Indirect => continue,
                };
            decided.insert(bctr, decision);
        }
        decided
    }

    /// Follows every path from the entry of `function`, through the tables of `decided`.
    fn run(
        code: &Code<'_>,
        function: Function,
        rules: &'r Rules,
        decided: &BTreeMap<u32, Decided>,
    ) -> Result<Self, Error> {
        let mut walk = Self {
            function,
            rules,
            insns: BTreeMap::new(),
            leaders: BTreeSet::from([function.addr]),
            joins: BTreeSet::from([function.addr]),
            bctrs: BTreeSet::new(),
            tables: BTreeMap::new(),
            unresolved: BTreeSet::new(),
            rounds: 0,
        };
        let mut pending = vec![function.addr];
        for &join in rules.joins.range(function.addr..) {
            if !function.contains(join) {
                break;
            }
            walk.add_join(join, &mut pending);
        }
        while let Some(start) = pending.pop() {
            let mut addr = start;
            // A walk stops at a jump, at the end of the range, or where an earlier walk went, which
            // is always the start of a block.
            while function.contains(addr) && !walk.insns.contains_key(&addr) {
                let insn = decode_at(code, function, addr)?;
                walk.insns.insert(addr, insn);
                let Flow::Jump {
                    target,
                    conditional,
                } = flow(&insn, addr)
                else {
                    if rules.never_returns(&insn, addr) {
                        break;
                    }
                    if rules.returns_twice(&insn, addr) {
                        walk.add_leader(addr.wrapping_add(4), &mut pending);
                    }
                    addr = addr.wrapping_add(4);
                    continue;
                };
                match target {
                    Target::Address(target) => walk.add_join(target, &mut pending),
                    Target::Ctr if !conditional => walk.jump_table(addr, decided, &mut pending),
                    _ => {}
                }
                if conditional {
                    walk.add_leader(addr.wrapping_add(4), &mut pending);
                }
                break;
            }
        }
        Ok(walk)
    }

    /// Follows the table of the `bctr` at `addr`, if `decided` resolved it.
    fn jump_table(&mut self, addr: u32, decided: &BTreeMap<u32, Decided>, pending: &mut Vec<u32>) {
        self.bctrs.insert(addr);
        match decided.get(&addr) {
            Some(Decided::Table(table)) => {
                for &to in &table.targets {
                    self.add_join(to, pending);
                }
                self.tables.insert(addr, table.clone());
            }
            Some(Decided::Unresolved) => {
                self.unresolved.insert(addr);
            }
            None => {}
        }
    }

    /// Records the target of a branch or a table inside the function: a join and a block start.
    fn add_join(&mut self, addr: u32, pending: &mut Vec<u32>) {
        if self.function.contains(addr) {
            self.joins.insert(addr);
            self.add_leader(addr, pending);
        }
    }

    /// Records a block start inside the function, and queues it if it is new.
    fn add_leader(&mut self, addr: u32, pending: &mut Vec<u32>) {
        if self.function.contains(addr) && self.leaders.insert(addr) {
            pending.push(addr);
        }
    }

    /// Builds the block that starts at `start`, from the instructions the walk decoded.
    fn block(&self, start: u32) -> Block {
        let mut insns = Vec::new();
        let mut addr = start;
        loop {
            let insn = self.insns[&addr];
            insns.push((addr, insn));
            let next = addr.wrapping_add(4);
            let exit = match flow(&insn, addr) {
                Flow::Jump {
                    conditional: false, ..
                } => Some(Exit::Jump),
                Flow::Jump {
                    conditional: true, ..
                } => Some(self.exit_to(next)),
                Flow::Next if self.rules.never_returns(&insn, addr) => Some(Exit::NoReturn),
                Flow::Next if !self.function.contains(next) || self.leaders.contains(&next) => {
                    Some(self.exit_to(next))
                }
                Flow::Next => None,
            };
            if let Some(exit) = exit {
                return Block { start, insns, exit };
            }
            addr = next;
        }
    }

    /// The exit to the next instruction: a block, or off the end of the function.
    fn exit_to(&self, next: u32) -> Exit {
        if self.function.contains(next) {
            Exit::Next(next)
        } else {
            Exit::FallOff
        }
    }
}

fn decode_at(code: &Code<'_>, function: Function, addr: u32) -> Result<Insn, Error> {
    let word = code.word(addr).ok_or(Error::OutsideCode {
        function: function.addr,
        addr,
    })?;
    decode(word).ok_or(Error::Undecodable {
        function: function.addr,
        addr,
        word,
    })
}
