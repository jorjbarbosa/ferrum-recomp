// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The dominators of the nodes of a [`Graph`]: a node dominates another when every path from the
//! entry to the other goes through it.
//!
//! The algorithm is the one of Cooper, Harvey and Kennedy, "A Simple, Fast Dominance Algorithm"
//! (Software Practice and Experience, 2001): it visits the nodes in reverse postorder and makes
//! the immediate dominator of each the nearest common ancestor, in the tree built so far, of its
//! predecessors already visited, until a round changes nothing. Its authors found it faster than
//! the Lengauer-Tarjan algorithm on the control-flow graphs of real programs.

use super::graph::{Graph, NodeId, Order};

/// The immediate dominator of every node of a [`Graph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dominators {
    /// The immediate dominator of each node; the entry's is the entry.
    idom: Vec<NodeId>,
}

impl Dominators {
    /// The dominators of `graph`, whose reverse postorder is `order`.
    pub fn new(graph: &Graph, order: &Order) -> Self {
        let predecessors = graph.predecessors();
        let entry = order.nodes()[0];
        let mut idom: Vec<Option<NodeId>> = vec![None; graph.nodes().len()];
        idom[entry] = Some(entry);
        let mut changed = true;
        while changed {
            changed = false;
            for &node in &order.nodes()[1..] {
                let mut new = None;
                for &predecessor in &predecessors[node] {
                    if idom[predecessor].is_none() {
                        continue;
                    }
                    new = Some(match new {
                        None => predecessor,
                        Some(other) => intersect(&idom, order, predecessor, other),
                    });
                }
                if new.is_some() && idom[node] != new {
                    idom[node] = new;
                    changed = true;
                }
            }
        }
        let idom = idom
            .into_iter()
            // In reverse postorder, a node's parent in the walk comes before it, so every node
            // has a visited predecessor by the end of the first round.
            .map(|idom| idom.expect("every node has a visited predecessor"))
            .collect();
        Self { idom }
    }

    /// The immediate dominator of `node`: the entry's is the entry.
    pub fn idom(&self, node: NodeId) -> NodeId {
        self.idom[node]
    }

    /// Whether `a` dominates `b`. A node dominates itself.
    pub fn dominates(&self, a: NodeId, b: NodeId) -> bool {
        let mut node = b;
        loop {
            if node == a {
                return true;
            }
            let up = self.idom[node];
            if up == node {
                return false;
            }
            node = up;
        }
    }
}

/// The nearest common ancestor of `a` and `b` in the dominator tree built so far, climbing from
/// the one later in the order.
fn intersect(idom: &[Option<NodeId>], order: &Order, mut a: NodeId, mut b: NodeId) -> NodeId {
    let up = |node: NodeId| {
        // Only nodes that have an immediate dominator are climbed from, and their ancestors are
        // earlier in the order, so they have one too.
        idom[node].expect("an ancestor in the tree has an immediate dominator")
    };
    while a != b {
        while order.number(a) > order.number(b) {
            a = up(a);
        }
        while order.number(b) > order.number(a) {
            b = up(b);
        }
    }
    a
}
