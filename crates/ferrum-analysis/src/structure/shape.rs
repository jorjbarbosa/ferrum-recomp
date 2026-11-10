// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The structured form of a function: a tree of labeled blocks, loops and the code of nodes, in
//! which every site says how it reaches its node.
//!
//! The tree lives in an arena, a list indexed by [`ShapeId`], so that building it, walking it and
//! dropping it need no recursion: a function of several thousand blocks would otherwise risk the
//! stack.

use super::graph::NodeId;

/// The index of a [`Shape`] in a [`Structure`].
pub type ShapeId = usize;

/// The structured form of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Structure {
    /// The shapes, which refer to one another by index.
    pub shapes: Vec<Shape>,
    /// The shape of the whole function.
    pub root: ShapeId,
}

/// One piece of the structured form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// The code of a node, and for each of its sites, in order, how it reaches its node.
    Code {
        /// The node whose code this is.
        node: NodeId,
        /// One branch for each site of the node.
        sites: Vec<Branch>,
    },
    /// A loop whose body starts with the code of `header`, a node that sites go back to. Every
    /// path of the body ends in a transfer, so the body never runs into its end.
    Loop {
        /// The node at the top of the loop.
        header: NodeId,
        /// The body of the loop.
        body: ShapeId,
    },
    /// A labeled block, then the code of `follow`, a node that several sites reach: a site of the
    /// body that leaves the block goes there. Every path of the body ends in a transfer.
    Labeled {
        /// The node whose code follows the block.
        follow: NodeId,
        /// The body of the block.
        body: ShapeId,
        /// The code that follows it, which starts with the code of `follow`.
        then: ShapeId,
    },
}

/// How one site reaches its node. `state`, for a site that goes to a dispatch node, is the address
/// of the entry it chooses there, written before the transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    /// Back to the top of the enclosing loop whose header is `to`.
    Continue {
        /// The header of the loop.
        to: NodeId,
        /// The entry chosen at a dispatch node.
        state: Option<u32>,
    },
    /// Out of the enclosing labeled block that `to` follows.
    Break {
        /// The node that follows the block.
        to: NodeId,
        /// The entry chosen at a dispatch node.
        state: Option<u32>,
    },
    /// Into the code of `to`, written in place: the site is the only one that reaches `to` from
    /// a node before it in the order.
    Inline {
        /// The node.
        to: NodeId,
        /// The entry chosen at a dispatch node.
        state: Option<u32>,
        /// Its shape.
        code: ShapeId,
    },
}

impl Branch {
    /// The node the site reaches.
    pub fn to(self) -> NodeId {
        match self {
            Branch::Continue { to, .. } | Branch::Break { to, .. } | Branch::Inline { to, .. } => {
                to
            }
        }
    }

    /// The entry the site chooses at a dispatch node, if it goes to one.
    pub fn state(self) -> Option<u32> {
        match self {
            Branch::Continue { state, .. }
            | Branch::Break { state, .. }
            | Branch::Inline { state, .. } => state,
        }
    }
}
