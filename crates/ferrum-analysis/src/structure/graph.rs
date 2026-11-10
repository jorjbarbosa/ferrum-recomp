// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The graph that the structuring of a function works on, and the order of its nodes.
//!
//! A node is a block of the function, or a dispatch node that the structuring adds. A node's
//! sites are the places in its code that send control to another node, in the order the code
//! writes them. An edge is a site, not a pair of nodes: a node can reach the same node from two
//! sites, as a conditional branch to the next block does, and both count.

use std::cmp::Reverse;
use std::collections::BTreeMap;

/// The index of a node in a [`Graph`]. The entry is node 0.
pub type NodeId = usize;

/// What a node of a [`Graph`] stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// The block that starts at this address.
    Block(u32),
    /// A dispatch node, which the structuring puts in front of a cycle that several of its nodes
    /// enter. It holds no code of the guest: it goes to the entry that the site which reached it
    /// chose. The address is that of its lowest entry, which names it.
    Dispatch(u32),
}

impl NodeKind {
    /// The address that names the node.
    pub fn addr(self) -> u32 {
        match self {
            NodeKind::Block(addr) | NodeKind::Dispatch(addr) => addr,
        }
    }
}

/// A site: one place in the code of a node that sends control to another node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    /// The node it goes to.
    pub to: NodeId,
    /// For a site that goes to a dispatch node, the address of the entry it chooses there.
    pub state: Option<u32>,
}

/// A node of a [`Graph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// What the node stands for.
    pub kind: NodeKind,
    /// The sites of the node, in the order its code writes them.
    pub sites: Vec<Edge>,
}

/// The nodes of one function and their sites. Every node is reachable from the entry, node 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graph {
    nodes: Vec<Node>,
    /// The node of each block, by the block's start.
    blocks: BTreeMap<u32, NodeId>,
}

impl Graph {
    /// Builds the graph of a function from its blocks: for each block, its start and the starts
    /// of the blocks its sites go to, in the order its code writes them. The first block is the
    /// entry. A block that no path from the entry reaches is left out; the others keep their
    /// order.
    ///
    /// Panics if `blocks` is empty or a site goes to an address where none of `blocks` starts:
    /// the caller lists the sites of the blocks it gives.
    pub fn from_blocks(blocks: &[(u32, Vec<u32>)]) -> Self {
        assert!(!blocks.is_empty(), "a function has an entry block");
        let index: BTreeMap<u32, usize> = blocks
            .iter()
            .enumerate()
            .map(|(index, &(start, _))| (start, index))
            .collect();
        let target = |addr: u32| match index.get(&addr) {
            Some(&index) => index,
            None => panic!("a site goes to {addr:#010x}, where no block starts"),
        };
        let mut reached = vec![false; blocks.len()];
        reached[0] = true;
        let mut stack = vec![0];
        while let Some(block) = stack.pop() {
            for &to in &blocks[block].1 {
                let to = target(to);
                if !reached[to] {
                    reached[to] = true;
                    stack.push(to);
                }
            }
        }
        let mut id = vec![None; blocks.len()];
        for (next, index) in (0..blocks.len()).filter(|&i| reached[i]).enumerate() {
            id[index] = Some(next);
        }
        let node = |to: u32| -> NodeId {
            // Every target of a reached block is reached.
            id[target(to)].expect("the target of a reached block is reached")
        };
        let nodes = blocks
            .iter()
            .zip(&reached)
            .filter(|&(_, &reached)| reached)
            .map(|((start, targets), _)| Node {
                kind: NodeKind::Block(*start),
                sites: targets
                    .iter()
                    .map(|&to| Edge {
                        to: node(to),
                        state: None,
                    })
                    .collect(),
            })
            .collect();
        Self::from_nodes(nodes)
    }

    /// A graph of `nodes`, whose sites already refer to nodes by index.
    pub(crate) fn from_nodes(nodes: Vec<Node>) -> Self {
        let blocks = nodes
            .iter()
            .enumerate()
            .filter_map(|(id, node)| match node.kind {
                NodeKind::Block(start) => Some((start, id)),
                NodeKind::Dispatch(_) => None,
            })
            .collect();
        Self { nodes, blocks }
    }

    /// The nodes, by index.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The node `id`.
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

    /// The node of the block that starts at `start`, if that block is reachable.
    pub fn node_of(&self, start: u32) -> Option<NodeId> {
        self.blocks.get(&start).copied()
    }

    /// The predecessors of each node, once for each site that goes to it.
    pub fn predecessors(&self) -> Vec<Vec<NodeId>> {
        let mut predecessors = vec![Vec::new(); self.nodes.len()];
        for (from, node) in self.nodes.iter().enumerate() {
            for edge in &node.sites {
                predecessors[edge.to].push(from);
            }
        }
        predecessors
    }
}

/// The nodes of a [`Graph`] in reverse postorder of a depth-first walk from the entry.
///
/// The walk visits the successors of a node in decreasing order of their addresses, so that the
/// order follows the addresses of the blocks wherever the branches allow, and the generated code
/// reads in the order of the guest's. Ties, which only dispatch nodes can make, go by index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    /// The nodes in reverse postorder, the entry first.
    nodes: Vec<NodeId>,
    /// The position of each node in `nodes`.
    number: Vec<usize>,
}

impl Order {
    /// The reverse postorder of `graph`.
    ///
    /// Panics if some node is not reachable from the entry, which [`Graph`] rules out.
    pub fn new(graph: &Graph) -> Self {
        let count = graph.nodes.len();
        let successors: Vec<Vec<NodeId>> = graph
            .nodes
            .iter()
            .map(|node| {
                let mut successors: Vec<NodeId> = node.sites.iter().map(|edge| edge.to).collect();
                successors.sort_by_key(|&to| Reverse((graph.nodes[to].kind.addr(), to)));
                successors.dedup();
                successors
            })
            .collect();
        let mut visited = vec![false; count];
        let mut postorder = Vec::with_capacity(count);
        // Each entry is a node of the walk and how many of its successors it has looked at.
        let mut stack = vec![(0, 0)];
        visited[0] = true;
        while let Some(top) = stack.last_mut() {
            let (node, next) = *top;
            match successors[node].get(next) {
                Some(&successor) => {
                    top.1 += 1;
                    if !visited[successor] {
                        visited[successor] = true;
                        stack.push((successor, 0));
                    }
                }
                None => {
                    postorder.push(node);
                    stack.pop();
                }
            }
        }
        assert!(
            postorder.len() == count,
            "every node of a graph is reachable from its entry"
        );
        postorder.reverse();
        let mut number = vec![0; count];
        for (position, &node) in postorder.iter().enumerate() {
            number[node] = position;
        }
        Self {
            nodes: postorder,
            number,
        }
    }

    /// The nodes in reverse postorder, the entry first.
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }

    /// The position of `node` in the order.
    pub fn number(&self, node: NodeId) -> usize {
        self.number[node]
    }

    /// Whether a site from `from` to `to` goes back: `to` comes no later than `from` in the order.
    /// In a walk from the entry, such a site goes to a node of the walk's current path, so it
    /// closes a cycle.
    pub fn is_back(&self, from: NodeId, to: NodeId) -> bool {
        self.number[to] <= self.number[from]
    }
}
