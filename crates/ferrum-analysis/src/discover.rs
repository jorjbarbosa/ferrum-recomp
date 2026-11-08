// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Function discovery: which functions the code holds and where each one ends.
//!
//! The sources, in order of confidence, are `.pdata`, the entry point and the exports, branch
//! targets, pointers in data, a sweep of the gaps and the overrides of the config.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::ops::Range;
use std::rc::Rc;

use ferrum_decoder::Insn;

use crate::cfg::{Cfg, Exit, Function, Rules, build};
use crate::code::Code;
use crate::error::Error;
use crate::flow::{Flow, Target, branch_target, flow, links};
use crate::save_restore::SaveRestore;

/// The size of an import thunk: `lis`, `lwz`, `mtctr` and `bctr`.
pub const THUNK_SIZE: u32 = 16;

/// What discovery reads: the image, laid out by its sections, and the config.
#[derive(Debug, Clone)]
pub struct Input<'a> {
    /// The image, holding every byte of the ranges below.
    pub code: Code<'a>,
    /// The ranges of the executable sections, clipped to the bytes the image holds.
    pub code_ranges: Vec<Range<u32>>,
    /// The ranges of the sections whose words may point into code: every section that is
    /// neither code nor `.pdata`.
    pub data_ranges: Vec<Range<u32>>,
    /// The entries of `.pdata`, in any order.
    pub pdata: Vec<Function>,
    /// The entry point and the exports. Those that do not point into code are ignored.
    pub entries: Vec<u32>,
    /// The addresses of the import thunks, each [`THUNK_SIZE`] bytes long.
    pub thunks: BTreeSet<u32>,
    /// The save and restore routines, whose entries are not functions.
    pub routines: &'a SaveRestore,
    /// `[analysis] functions`: functions with a range, treated like `.pdata` entries.
    pub functions: Vec<Function>,
    /// `[analysis] skip`: ranges where no function starts and the sweep does not look.
    pub skip: Vec<Function>,
    /// `[analysis] jump_tables`: entry counts by the address of the `bctr`.
    pub table_entries: BTreeMap<u32, u32>,
    /// `[analysis] longjmp`: the address of the function that never returns by definition.
    pub longjmp: Option<u32>,
}

/// Where a function came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// An entry of `.pdata`.
    Pdata,
    /// `[analysis] functions`.
    Override,
    /// The entry point or an export.
    Entry,
    /// The target of a call, of a branch out of a function, or of a jump table.
    Branch,
    /// A branch target inside the range of a `.pdata` function or an override.
    SecondEntry,
    /// A pointer in a data section.
    Pointer,
    /// The sweep of a gap, after the end of the function before it.
    Sweep,
}

/// Something suspicious that does not stop discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// A `.pdata` entry overlaps an earlier one and was dropped.
    PdataOverlap {
        /// Entry of the dropped function.
        addr: u32,
        /// Entry of the function it overlaps.
        previous: u32,
    },
    /// A call or branch targets an address outside the code.
    TargetOutsideCode {
        /// Address of the branch.
        from: u32,
        /// The target.
        target: u32,
    },
    /// A `bctr` loads CTR from a table that could not be resolved.
    UnresolvedJumpTable {
        /// Entry of the function.
        function: u32,
        /// Address of the `bctr`.
        bctr: u32,
    },
    /// A path runs off the end of the function, and no function starts there.
    FallsOff {
        /// Entry of the function.
        function: u32,
    },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Warning::PdataOverlap { addr, previous } => write!(
                f,
                ".pdata entry {addr:#010x} overlaps the function at {previous:#010x}; dropped"
            ),
            Warning::TargetOutsideCode { from, target } => write!(
                f,
                "the branch at {from:#010x} targets {target:#010x}, outside the code"
            ),
            Warning::UnresolvedJumpTable { function, bctr } => write!(
                f,
                "unresolved jump table at {bctr:#010x} in {function:#010x}; the bctr becomes a \
                 dynamic lookup"
            ),
            Warning::FallsOff { function } => write!(
                f,
                "a path runs off the end of the function at {function:#010x}"
            ),
        }
    }
}

/// The functions found, and what code generation needs to build them as discovery did.
#[derive(Debug, Clone)]
pub struct Discovery {
    /// The functions, by entry. Ranges may overlap where a function has a second entry.
    pub functions: Vec<Function>,
    /// Where each function came from, by entry.
    pub sources: BTreeMap<u32, Source>,
    /// The functions that never return and the jump table counts of the config.
    pub rules: Rules,
    /// Suspicious things found on the way.
    pub warnings: Vec<Warning>,
}

/// What discovery needs from the blocks of one function.
#[derive(Debug, Default)]
struct Summary {
    /// One past the last instruction reached.
    reach: u64,
    /// Every instruction reached.
    reached: Vec<u32>,
    /// Calls and branches out with a fixed target: the branch and its target.
    targets: Vec<(u32, u32)>,
    /// Whether a path returns, or leaves through a branch whose target is not known.
    returns: bool,
    /// The fixed targets of the branches that leave the function, and the end of the range if a
    /// path runs into it: the function returns if any of them does.
    exits: Vec<u32>,
}

/// Discovers the functions of `input`.
///
/// Fails if a path of a function found from a source above the sweep reaches a word that does
/// not decode.
pub fn discover(input: &Input<'_>) -> Result<Discovery, Error> {
    Discoverer::new(input).run()
}

struct Discoverer<'i, 'a> {
    input: &'i Input<'a>,
    /// Functions whose range is given: `.pdata`, overrides and second entries.
    fixed: BTreeMap<u32, Function>,
    /// The ranges of the `.pdata` entries and overrides, by start, for second entries.
    ranges: BTreeMap<u32, u64>,
    /// The code that no range covers, minus the skipped ranges.
    gaps: Vec<Range<u64>>,
    /// Entries in the gaps.
    entries: BTreeMap<u32, Source>,
    /// The functions of the last sweep.
    swept: Vec<Function>,
    sources: BTreeMap<u32, Source>,
    rules: Rules,
    warnings: Vec<Warning>,
    outside: HashSet<u32>,
    cache: HashMap<Function, Result<Rc<Summary>, Error>>,
}

impl<'i, 'a> Discoverer<'i, 'a> {
    fn new(input: &'i Input<'a>) -> Self {
        let mut this = Self {
            input,
            fixed: BTreeMap::new(),
            ranges: BTreeMap::new(),
            gaps: Vec::new(),
            entries: BTreeMap::new(),
            swept: Vec::new(),
            sources: BTreeMap::new(),
            rules: Rules {
                no_return: input.longjmp.into_iter().collect(),
                table_entries: input.table_entries.clone(),
                returns_twice: BTreeSet::new(),
                joins: BTreeSet::new(),
            },
            warnings: Vec::new(),
            outside: HashSet::new(),
            cache: HashMap::new(),
        };
        this.add_ranges();
        this.gaps = this.find_gaps();
        for &entry in &input.entries {
            if this.in_code(entry) {
                this.add_target(None, entry, Source::Entry);
            }
        }
        this
    }

    fn run(mut self) -> Result<Discovery, Error> {
        let mut pointers_added = false;
        loop {
            self.settle()?;
            let no_return = self.no_return()?;
            if no_return != self.rules.no_return {
                self.rules.no_return = no_return;
                self.cache.clear();
                continue;
            }
            if !pointers_added {
                pointers_added = true;
                if self.add_pointers()? {
                    continue;
                }
            }
            break;
        }
        self.finish()
    }

    /// The `.pdata` entries and overrides: functions with a range, which the gaps leave out.
    fn add_ranges(&mut self) {
        let mut pdata: Vec<Function> = self.input.pdata.clone();
        pdata.sort_by_key(|f| f.addr);
        let mut previous: Option<Function> = None;
        for function in pdata {
            if !self.whole_in_code(function) || self.skipped(function.addr) {
                continue;
            }
            if let Some(prev) = previous.filter(|prev| u64::from(function.addr) < prev.end()) {
                self.warnings.push(Warning::PdataOverlap {
                    addr: function.addr,
                    previous: prev.addr,
                });
                continue;
            }
            previous = Some(function);
            self.add_fixed(function, Source::Pdata);
        }
        for &function in &self.input.functions {
            self.add_fixed(function, Source::Override);
        }
    }

    fn add_fixed(&mut self, function: Function, source: Source) {
        if source != Source::SecondEntry {
            self.ranges.insert(function.addr, function.end());
        }
        self.fixed.insert(function.addr, function);
        self.sources.insert(function.addr, source);
    }

    fn find_gaps(&self) -> Vec<Range<u64>> {
        let mut holes: Vec<Range<u64>> = self
            .ranges
            .iter()
            .map(|(&start, &end)| u64::from(start)..end)
            .chain(self.input.skip.iter().map(|f| u64::from(f.addr)..f.end()))
            .collect();
        holes.sort_by_key(|range| range.start);
        let mut gaps = Vec::new();
        for code in &self.input.code_ranges {
            let mut start = u64::from(code.start);
            let end = u64::from(code.end);
            for hole in &holes {
                if hole.end <= start || hole.start >= end {
                    continue;
                }
                if hole.start > start {
                    gaps.push(start..hole.start);
                }
                start = start.max(hole.end);
            }
            if start < end {
                gaps.push(start..end);
            }
        }
        gaps
    }

    /// Walks every function until no branch target is new.
    fn settle(&mut self) -> Result<(), Error> {
        loop {
            let mut changed = false;
            let fixed: Vec<Function> = self.fixed.values().copied().collect();
            for function in fixed {
                if let Ok(summary) = self.summary(function) {
                    changed |= self.add_targets(&summary);
                }
            }
            self.swept = self.sweep()?;
            for function in self.swept.clone() {
                if let Ok(summary) = self.summary(function) {
                    changed |= self.add_targets(&summary);
                }
            }
            if !changed {
                return Ok(());
            }
        }
    }

    /// Splits every gap into functions.
    fn sweep(&mut self) -> Result<Vec<Function>, Error> {
        let mut found = Vec::new();
        for gap in self.gaps.clone() {
            let mut cursor = gap.start.next_multiple_of(4);
            while cursor + 4 <= gap.end {
                // The gaps lie in the 32-bit address space.
                let addr = cursor as u32;
                if self.input.thunks.contains(&addr) {
                    cursor += u64::from(THUNK_SIZE);
                    continue;
                }
                let entry = self.entries.contains_key(&addr);
                if !entry && self.input.code.word(addr) == Some(0) {
                    cursor += 4;
                    continue;
                }
                let bound = self.bound(addr, gap.end);
                match self.sweep_one(addr, bound, entry)? {
                    Some(function) => {
                        found.push(function);
                        self.sources.entry(addr).or_insert(Source::Sweep);
                        cursor = function.end();
                    }
                    None => cursor += 4,
                }
            }
        }
        Ok(found)
    }

    /// The function of the sweep that starts at `addr`, whose range may not pass `bound`, or
    /// `None` if the word there is data. A path that reaches a word that does not decode ends the
    /// range before it, as a suspicious boundary.
    fn sweep_one(
        &mut self,
        addr: u32,
        mut bound: u64,
        entry: bool,
    ) -> Result<Option<Function>, Error> {
        loop {
            let candidate = Function {
                addr,
                // The bound is above `addr` and at most 2^32.
                size: (bound - u64::from(addr)) as u32,
            };
            match self.summary(candidate) {
                Ok(summary) => {
                    return Ok(Some(Function {
                        addr,
                        size: (summary.reach - u64::from(addr)) as u32,
                    }));
                }
                Err(Error::Undecodable { addr: at, .. }) if at > addr => bound = u64::from(at),
                Err(_) if !entry => return Ok(None),
                Err(error) => return Err(error),
            }
        }
    }

    /// The end of the range a function of the sweep starting at `addr` may take: the next entry
    /// or thunk, or the end of the gap.
    fn bound(&self, addr: u32, gap_end: u64) -> u64 {
        let after = addr.saturating_add(1);
        let next_entry = self.entries.range(after..).next().map(|(&a, _)| a);
        let next_thunk = self.input.thunks.range(after..).next().copied();
        [next_entry, next_thunk]
            .into_iter()
            .flatten()
            .map(u64::from)
            .fold(gap_end, u64::min)
    }

    /// Adds the targets of a function's branches; returns whether any was new.
    fn add_targets(&mut self, summary: &Summary) -> bool {
        let mut changed = false;
        for &(from, target) in &summary.targets {
            changed |= self.add_target(Some(from), target, Source::Branch);
        }
        changed
    }

    /// Records `target` as an entry, a second entry or nothing; returns whether it is new.
    fn add_target(&mut self, from: Option<u32>, target: u32, source: Source) -> bool {
        if self.input.routines.contains_key(&target)
            || self.input.thunks.contains(&target)
            || self.fixed.contains_key(&target)
            || self.skipped(target)
        {
            return false;
        }
        if !self.in_code(target) {
            if let Some(from) = from
                && self.outside.insert(target)
            {
                self.warnings
                    .push(Warning::TargetOutsideCode { from, target });
            }
            return false;
        }
        if let Some((&start, &end)) = self.ranges.range(..=target).next_back()
            && u64::from(target) < end
        {
            let second = Function {
                addr: target,
                size: (end - u64::from(target)) as u32,
            };
            debug_assert!(start < target);
            self.add_fixed(second, Source::SecondEntry);
            return true;
        }
        if self.entries.contains_key(&target) {
            return false;
        }
        self.entries.insert(target, source);
        self.sources.insert(target, source);
        true
    }

    /// The functions that never return, given the ones known so far: those whose every path
    /// ends in a call or branch to one that never returns.
    fn no_return(&mut self) -> Result<BTreeSet<u32>, Error> {
        let mut no_return = self.rules.no_return.clone();
        let functions: Vec<Function> = self.all_functions();
        for function in functions {
            if no_return.contains(&function.addr) {
                continue;
            }
            let Ok(summary) = self.summary(function) else {
                continue;
            };
            let returns = summary.returns
                || summary
                    .exits
                    .iter()
                    .any(|exit| !self.rules.no_return.contains(exit));
            if !returns {
                no_return.insert(function.addr);
            }
        }
        Ok(no_return)
    }

    /// Adds the pointers in data that start functions; returns whether any did.
    fn add_pointers(&mut self) -> Result<bool, Error> {
        let mut reached = HashSet::new();
        for function in self.swept.clone() {
            if let Ok(summary) = self.summary(function) {
                reached.extend(summary.reached.iter().copied());
            }
        }
        let starts: HashSet<u32> = self.swept.iter().map(|f| f.addr).collect();
        let mut added = false;
        for value in self.pointers() {
            if starts.contains(&value)
                || reached.contains(&value)
                || self.entries.contains_key(&value)
                || self.covered(value)
                || self.in_thunk(value)
                || self.input.routines.contains_key(&value)
                || self.skipped(value)
            {
                continue;
            }
            let Some(gap_end) = self.gap_end(value) else {
                continue;
            };
            let candidate = Function {
                addr: value,
                size: (self.bound(value, gap_end) - u64::from(value)) as u32,
            };
            if self.summary(candidate).is_ok() {
                self.entries.insert(value, Source::Pointer);
                self.sources.insert(value, Source::Pointer);
                added = true;
            }
        }
        Ok(added)
    }

    /// The aligned words of the data sections that hold an aligned address in the code.
    fn pointers(&self) -> BTreeSet<u32> {
        let code = &self.input.code;
        let mut found = BTreeSet::new();
        for range in &self.input.data_ranges {
            let mut addr = range.start.next_multiple_of(4);
            while u64::from(addr) + 4 <= u64::from(range.end) {
                if let Some(value) = code.word(addr)
                    && value.is_multiple_of(4)
                    && self.in_code(value)
                {
                    found.insert(value);
                }
                addr += 4;
            }
        }
        found
    }

    fn finish(mut self) -> Result<Discovery, Error> {
        let mut functions = self.all_functions();
        functions.sort_by_key(|f| f.addr);
        let entries: HashSet<u32> = functions.iter().map(|f| f.addr).collect();
        for &function in &functions {
            let cfg = build(&self.input.code, function, &self.rules)?;
            for &bctr in &cfg.unresolved {
                self.warnings.push(Warning::UnresolvedJumpTable {
                    function: function.addr,
                    bctr,
                });
            }
            let end = function.end();
            if cfg.falls_off() && !(end < 1 << 32 && entries.contains(&(end as u32))) {
                self.warnings.push(Warning::FallsOff {
                    function: function.addr,
                });
            }
        }
        let sources = functions
            .iter()
            .map(|f| (f.addr, self.sources[&f.addr]))
            .collect();
        Ok(Discovery {
            functions,
            sources,
            rules: self.rules,
            warnings: self.warnings,
        })
    }

    fn all_functions(&self) -> Vec<Function> {
        self.fixed
            .values()
            .copied()
            .chain(self.swept.iter().copied())
            .collect()
    }

    fn summary(&mut self, function: Function) -> Result<Rc<Summary>, Error> {
        if let Some(cached) = self.cache.get(&function) {
            return cached.clone();
        }
        let result =
            build(&self.input.code, function, &self.rules).map(|cfg| Rc::new(summarize(&cfg)));
        self.cache.insert(function, result.clone());
        result
    }

    fn in_code(&self, addr: u32) -> bool {
        self.input.code_ranges.iter().any(|r| r.contains(&addr))
    }

    fn whole_in_code(&self, function: Function) -> bool {
        self.input
            .code_ranges
            .iter()
            .any(|r| r.contains(&function.addr) && function.end() <= u64::from(r.end))
    }

    fn covered(&self, addr: u32) -> bool {
        self.ranges
            .range(..=addr)
            .next_back()
            .is_some_and(|(_, &end)| u64::from(addr) < end)
    }

    fn skipped(&self, addr: u32) -> bool {
        self.input.skip.iter().any(|range| range.contains(addr))
    }

    fn in_thunk(&self, addr: u32) -> bool {
        self.input
            .thunks
            .range(..=addr)
            .next_back()
            .is_some_and(|&thunk| u64::from(addr) < u64::from(thunk) + u64::from(THUNK_SIZE))
    }

    fn gap_end(&self, addr: u32) -> Option<u64> {
        let addr = u64::from(addr);
        self.gaps
            .iter()
            .find(|gap| gap.contains(&addr))
            .map(|gap| gap.end)
    }
}

/// What discovery needs from the blocks of a function.
fn summarize(cfg: &Cfg) -> Summary {
    let function = cfg.function;
    let mut summary = Summary {
        reach: cfg.reach(),
        ..Summary::default()
    };
    for block in &cfg.blocks {
        for &(at, insn) in &block.insns {
            summary.reached.push(at);
            if links(&insn)
                && let Some(Target::Address(to)) = branch_target(&insn, at)
            {
                summary.targets.push((at, to));
            }
        }
        let &(at, insn) = block.insns.last().expect("a block holds an instruction");
        match block.exit {
            Exit::FallOff => {
                // A path into the next function is a tail call to it; past the end of the
                // address space there is none.
                match u32::try_from(function.end()) {
                    Ok(end) => summary.exits.push(end),
                    Err(_) => summary.returns = true,
                }
            }
            Exit::NoReturn | Exit::Jump | Exit::Next(_) => {}
        }
        leaves(cfg, at, &insn, &mut summary);
    }
    summary
}

/// Records how the last instruction of a block may leave the function.
fn leaves(cfg: &Cfg, at: u32, insn: &Insn, summary: &mut Summary) {
    let Flow::Jump { target, .. } = flow(insn, at) else {
        return;
    };
    match target {
        Target::Lr => summary.returns = true,
        Target::Ctr if cfg.tables.contains_key(&at) => {}
        Target::Ctr => summary.returns = true,
        Target::Address(to) if cfg.function.contains(to) => {}
        Target::Address(to) => {
            summary.targets.push((at, to));
            summary.exits.push(to);
        }
    }
}

#[cfg(test)]
mod tests;
