// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The sites of a block: the places in its generated code that send control to another block of
//! the same function.
//!
//! A block's code transfers control at the taken side of a branch inside the function, on the path
//! that goes on into the next block, at each target of the resolved jump table that ends it, and at
//! the jump of a mid-asm hook. An edge between two blocks is one such site, not a pair of
//! addresses: a block can reach the same block from two sites, as a conditional branch to the next
//! block does, and the code then holds two transfers. Leaving the function (a return, a tail call,
//! an unresolved table, a call that never returns, falling off the end) is not a site.
//!
//! [`transfers`] lists the sites of a block in the order the emitter writes them. The emitter takes
//! them from that list one by one and checks each against the transfer it is about to write, so the
//! list holds exactly the transfers of the code, which is what the structuring of a function's
//! blocks needs to see.

use std::collections::BTreeSet;

use ferrum_analysis::{Block, Cfg, Exit, Flow, Function, Target, flow};

use crate::program::Program;

#[cfg(test)]
mod tests;

/// One place in the code of a block that sends control to a block of the same function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Site {
    /// What transfers control there.
    pub(crate) kind: SiteKind,
    /// The start of the block it goes to.
    pub(crate) target: u32,
}

/// What transfers control at a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SiteKind {
    /// A branch to an address inside the function: the whole branch if it is unconditional, its
    /// taken side if not.
    Branch,
    /// The path that goes on past the last instruction into the next block, or past a conditional
    /// branch that is not taken.
    Next,
    /// One target of the resolved jump table that ends the block. A target that several indexes
    /// share is one site.
    Table,
    /// The jump of a mid-asm hook.
    Hook,
}

/// The sites of `block`, a block of `cfg`, the blocks of `function`, in the order the emitter
/// writes them: for each instruction, the jumps of the hooks that come before it, its own sites,
/// and the jumps of the hooks that come after it; then the path into the next block, unless the
/// last instruction is a branch, whose own sites already include it.
pub(crate) fn transfers(
    program: &Program<'_>,
    function: Function,
    cfg: &Cfg,
    block: &Block,
) -> Vec<Site> {
    let mut sites = Vec::new();
    let hooks = |sites: &mut Vec<Site>, at: u32, after: bool| {
        let jumps = program
            .hooks_at(at)
            .filter(|hook| hook.after == after)
            .filter_map(|hook| hook.action.target());
        sites.extend(jumps.map(|target| Site {
            kind: SiteKind::Hook,
            target,
        }));
    };
    let mut ends_in_branch = false;
    for &(at, insn) in &block.insns {
        hooks(&mut sites, at, false);
        if let Flow::Jump {
            target,
            conditional,
        } = flow(&insn, at)
        {
            ends_in_branch = true;
            if let Some(table) = cfg.tables.get(&at) {
                let distinct: BTreeSet<u32> = table.targets.iter().copied().collect();
                sites.extend(distinct.into_iter().map(|target| Site {
                    kind: SiteKind::Table,
                    target,
                }));
            } else {
                if let Target::Address(to) = target
                    && function.contains(to)
                {
                    sites.push(Site {
                        kind: SiteKind::Branch,
                        target: to,
                    });
                }
                if conditional {
                    sites.extend(next(block.exit));
                }
            }
        }
        hooks(&mut sites, at, true);
    }
    if !ends_in_branch {
        sites.extend(next(block.exit));
    }
    sites
}

/// The site of the path that goes on past the end of a block, if it goes into a block of the
/// function.
fn next(exit: Exit) -> Option<Site> {
    match exit {
        Exit::Next(target) => Some(Site {
            kind: SiteKind::Next,
            target,
        }),
        Exit::Jump | Exit::FallOff | Exit::NoReturn => None,
    }
}
