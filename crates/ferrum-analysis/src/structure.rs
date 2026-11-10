// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The structuring of a function's blocks into labeled blocks and loops, so that generated code
//! can follow the guest's branches with `break`, `continue` and `if`, instead of a loop over a
//! `match` on the address of the next block.
//!
//! A [`Graph`] holds the blocks of a function and their sites, the places in their code that send
//! control to another block. [`Order`] puts its nodes in reverse postorder and [`Dominators`] finds
//! which node every path to another goes through. [`make_reducible`] puts a dispatch node in front
//! of every cycle with several entries, so that every cycle can be a loop. A [`Structure`] is the
//! structured form, a tree of [`Shape`]s in which each site is a [`Branch`]: back to a loop, out of
//! a labeled block, or into code written in place, the form of Norman Ramsey's "Beyond Relooper:
//! Recursive Translation of Unstructured Control Flow to Structured Control Flow" (ICFP 2022).

mod dominators;
mod graph;
mod reducible;
mod shape;
mod translate;
mod verify;

#[cfg(test)]
mod tests;

pub use dominators::Dominators;
pub use graph::{Edge, Graph, Node, NodeId, NodeKind, Order};
pub use reducible::{Reducible, is_reducible, make_reducible};
pub use shape::{Branch, Shape, ShapeId, Structure};
pub use verify::{Rejected, verify};

/// A function's graph in structured form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Structured {
    /// The graph the form is of: the function's, with a dispatch node in front of every cycle
    /// that several of its nodes enter.
    pub graph: Graph,
    /// The structured form, which [`verify`] accepted.
    pub structure: Structure,
    /// How many dispatch nodes the graph needed.
    pub dispatch_nodes: usize,
    /// How many sites go to a dispatch node instead of an entry of its cycle.
    pub redirected_sites: usize,
}

/// The structured form of `graph`, the graph of a function: dispatch nodes where cycles have
/// several entries, then Ramsey's translation, then [`verify`]. A rejection is a bug of the
/// structuring.
pub fn structure(graph: &Graph) -> Result<Structured, Rejected> {
    let Reducible {
        graph: reducible,
        dispatch_nodes,
        redirected_sites,
    } = make_reducible(graph);
    let order = Order::new(&reducible);
    let dominators = Dominators::new(&reducible, &order);
    let structure = translate::translate(&reducible, &order, &dominators);
    verify(graph, &reducible, &structure)?;
    Ok(Structured {
        graph: reducible,
        structure,
        dispatch_nodes,
        redirected_sites,
    })
}
