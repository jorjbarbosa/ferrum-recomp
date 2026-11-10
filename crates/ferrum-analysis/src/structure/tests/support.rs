// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! What the tests of the structuring share: random graphs, the dominators by their definition, and
//! two ways of running a function on a stream of decisions, through its graph and through its
//! structured form, which have to visit the same blocks.

use std::collections::{BTreeMap, BTreeSet};

use super::super::{Branch, Graph, NodeId, NodeKind, Shape, ShapeId, Structure};

/// A pseudo-random generator with a seed, SplitMix64 (Steele, Lea and Flood, "Fast Splittable
/// Pseudorandom Number Generators", OOPSLA 2014), so that a failing case can be run again.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number below `bound`, which must not be 0.
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

/// The address of the `index`th block of a test function.
pub(crate) fn addr(index: usize) -> u32 {
    0x8200_0000 + 0x10 * index as u32
}

/// The blocks of a random function of `count` blocks, each with up to `max_sites` sites to any
/// block, the same block twice included.
pub(crate) fn random_blocks(rng: &mut Rng, count: usize, max_sites: usize) -> Vec<(u32, Vec<u32>)> {
    (0..count)
        .map(|index| {
            let sites = rng.below(max_sites + 1);
            let targets = (0..sites).map(|_| addr(rng.below(count))).collect();
            (addr(index), targets)
        })
        .collect()
}

/// The dominators of every node by their definition: the entry's are itself, and another node's
/// are itself and the nodes that dominate all its predecessors, worked out until nothing changes.
pub(crate) fn dominator_sets(graph: &Graph) -> Vec<BTreeSet<NodeId>> {
    let count = graph.nodes().len();
    let predecessors = graph.predecessors();
    let all: BTreeSet<NodeId> = (0..count).collect();
    let mut sets = vec![all; count];
    sets[0] = BTreeSet::from([0]);
    let mut changed = true;
    while changed {
        changed = false;
        for (node, predecessors) in predecessors.iter().enumerate().skip(1) {
            let mut set = predecessors
                .iter()
                .map(|&p| sets[p].clone())
                .reduce(|a, b| a.intersection(&b).copied().collect())
                .unwrap_or_default();
            set.insert(node);
            if set != sets[node] {
                sets[node] = set;
                changed = true;
            }
        }
    }
    sets
}

/// The choice made at a block with `sites` sites: one of them, or leaving the function, about
/// one time in sixteen and always where there is no site.
pub(crate) fn decide(rng: &mut Rng, sites: usize) -> Option<usize> {
    if sites == 0 {
        return None;
    }
    let draw = rng.next();
    (!draw.is_multiple_of(16)).then(|| ((draw >> 8) % sites as u64) as usize)
}

/// How many steps a run may take through dispatch nodes and shapes for each block it visits, so
/// that a wrong form that loops without visiting a block stops.
const STEPS_PER_BLOCK: usize = 64;

/// The blocks a run of `graph` visits, by address, with the decisions of `seed`, up to `cap`
/// blocks. A dispatch node goes to the entry its state names, without a decision.
pub(crate) fn walk(graph: &Graph, seed: u64, cap: usize) -> Result<Vec<u32>, String> {
    let mut rng = Rng::new(seed);
    let mut trace = Vec::new();
    let mut state: BTreeMap<NodeId, u32> = BTreeMap::new();
    let mut node = 0;
    for _ in 0..cap * STEPS_PER_BLOCK {
        let current = graph.node(node);
        let edge = match current.kind {
            NodeKind::Block(start) => {
                if trace.len() == cap {
                    return Ok(trace);
                }
                trace.push(start);
                match decide(&mut rng, current.sites.len()) {
                    Some(site) => current.sites[site],
                    None => return Ok(trace),
                }
            }
            NodeKind::Dispatch(_) => {
                let chosen = *state
                    .get(&node)
                    .ok_or_else(|| format!("node {node}: a dispatch node reached with no state"))?;
                *current
                    .sites
                    .iter()
                    .find(|edge| graph.node(edge.to).kind.addr() == chosen)
                    .ok_or_else(|| format!("node {node}: no entry at {chosen:#010x}"))?
            }
        };
        if let Some(chosen) = edge.state {
            state.insert(edge.to, chosen);
        }
        node = edge.to;
    }
    Err(format!("the walk did not end: {trace:x?}"))
}

/// What encloses the code being run: a loop, which a `continue` to its header runs again, or a
/// labeled block, which a `break` to the node it precedes leaves.
enum Frame {
    Loop { header: NodeId, body: ShapeId },
    Labeled { follow: NodeId, then: ShapeId },
}

/// The blocks a run of `structure`, the structured form of `graph`, visits, with the decisions of
/// `seed`, up to `cap` blocks: what generated code from the form would do, given the same choices.
/// An error says how the form is not one Rust would run, such as a `break` with no enclosing block.
pub(crate) fn interpret(
    graph: &Graph,
    structure: &Structure,
    seed: u64,
    cap: usize,
) -> Result<Vec<u32>, String> {
    let mut rng = Rng::new(seed);
    let mut trace = Vec::new();
    let mut state: BTreeMap<NodeId, u32> = BTreeMap::new();
    let mut frames: Vec<Frame> = Vec::new();
    let mut current = structure.root;
    for _ in 0..cap * STEPS_PER_BLOCK {
        let shape = structure
            .shapes
            .get(current)
            .ok_or_else(|| format!("no shape {current}"))?;
        let (node, sites) = match shape {
            Shape::Loop { header, body } => {
                frames.push(Frame::Loop {
                    header: *header,
                    body: *body,
                });
                current = *body;
                continue;
            }
            Shape::Labeled { follow, body, then } => {
                frames.push(Frame::Labeled {
                    follow: *follow,
                    then: *then,
                });
                current = *body;
                continue;
            }
            Shape::Code { node, sites } => (*node, sites),
        };
        let graph_node = graph.node(node);
        if sites.len() != graph_node.sites.len() {
            return Err(format!(
                "node {node}: {} branches for {} sites",
                sites.len(),
                graph_node.sites.len()
            ));
        }
        let site = match graph_node.kind {
            NodeKind::Block(start) => {
                if trace.len() == cap {
                    return Ok(trace);
                }
                trace.push(start);
                match decide(&mut rng, sites.len()) {
                    Some(site) => site,
                    None => return Ok(trace),
                }
            }
            NodeKind::Dispatch(_) => {
                let chosen = *state
                    .get(&node)
                    .ok_or_else(|| format!("node {node}: a dispatch node reached with no state"))?;
                graph_node
                    .sites
                    .iter()
                    .position(|edge| graph.node(edge.to).kind.addr() == chosen)
                    .ok_or_else(|| format!("node {node}: no entry at {chosen:#010x}"))?
            }
        };
        let branch = sites[site];
        if branch.to() != graph_node.sites[site].to {
            return Err(format!(
                "node {node}: site {site} goes to node {} in the form and {} in the graph",
                branch.to(),
                graph_node.sites[site].to
            ));
        }
        if let Some(chosen) = branch.state() {
            state.insert(branch.to(), chosen);
        }
        current = match branch {
            Branch::Inline { code, .. } => code,
            Branch::Continue { to, .. } => loop {
                match frames.last() {
                    Some(Frame::Loop { header, body }) if *header == to => break *body,
                    Some(_) => {
                        frames.pop();
                    }
                    None => return Err(format!("node {node}: continue to {to} outside its loop")),
                }
            },
            Branch::Break { to, .. } => loop {
                match frames.pop() {
                    Some(Frame::Labeled { follow, then }) if follow == to => break then,
                    Some(_) => {}
                    None => return Err(format!("node {node}: break to {to} outside its block")),
                }
            },
        };
    }
    Err(format!("the run did not end: {trace:x?}"))
}
