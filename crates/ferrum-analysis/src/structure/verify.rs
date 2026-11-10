// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The check of a structured form against the graphs it came from.
//!
//! Generated code follows the structured form, so a wrong form is wrong code. The check works the
//! order and the dominators out again rather than trusting the translation's, and holds the form
//! to what makes it run as the graph: every node written once; every site written once, as a
//! `continue` to a loop around it on a site that goes back, a `break` out of a block around it, or
//! the code of a node that only this site reaches from before it; every loop starting with its
//! header and every labeled block followed by its node. It also holds the dispatch nodes to the
//! original graph: a redirected site records the entry its original target was, a dispatch node
//! goes to exactly the entries its sites record, and only sites to a dispatch node record one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::dominators::Dominators;
use super::graph::{Graph, NodeId, NodeKind, Order};
use super::reducible::is_reducible;
use super::shape::{Branch, Shape, ShapeId, Structure};

/// Why a structured form was rejected. A rejection is a bug of the structuring, never of the guest
/// code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected(pub String);

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Rejected {}

/// Checks `structure`, the structured form of `reducible`, which is `original` with dispatch nodes.
pub fn verify(original: &Graph, reducible: &Graph, structure: &Structure) -> Result<(), Rejected> {
    check_dispatch(original, reducible)?;
    if !is_reducible(reducible) {
        return reject("the graph with its dispatch nodes is not reducible");
    }
    check_shapes(reducible, structure)
}

fn reject<T>(why: impl Into<String>) -> Result<T, Rejected> {
    Err(Rejected(why.into()))
}

/// The dispatch nodes against the original graph.
fn check_dispatch(original: &Graph, reducible: &Graph) -> Result<(), Rejected> {
    let blocks = original.nodes().len();
    if reducible.nodes().len() < blocks {
        return reject("the graph with dispatch nodes lost nodes");
    }
    // The entries that the sites redirected to each dispatch node chose.
    let mut chosen: BTreeMap<NodeId, BTreeSet<u32>> = BTreeMap::new();
    for (index, (before, after)) in original.nodes().iter().zip(reducible.nodes()).enumerate() {
        if before.kind != after.kind || before.sites.len() != after.sites.len() {
            return reject(format!("node {index} changed"));
        }
        for (site, (was, is)) in before.sites.iter().zip(&after.sites).enumerate() {
            match reducible.node(is.to).kind {
                NodeKind::Dispatch(_) => {
                    let entry = original.node(was.to).kind.addr();
                    if is.state != Some(entry) {
                        return reject(format!(
                            "node {index}, site {site}: records {:x?} for the entry {entry:#010x}",
                            is.state
                        ));
                    }
                    chosen.entry(is.to).or_default().insert(entry);
                }
                NodeKind::Block(_) if is != was => {
                    return reject(format!("node {index}, site {site} changed"));
                }
                NodeKind::Block(_) => {}
            }
        }
    }
    for (index, node) in reducible.nodes().iter().enumerate() {
        for (site, edge) in node.sites.iter().enumerate() {
            let to_dispatch = matches!(reducible.node(edge.to).kind, NodeKind::Dispatch(_));
            if edge.state.is_some() != to_dispatch {
                return reject(format!(
                    "node {index}, site {site}: a state is recorded only on a site to a dispatch \
                     node"
                ));
            }
        }
        if index < blocks {
            continue;
        }
        let NodeKind::Dispatch(addr) = node.kind else {
            return reject(format!("node {index}, added, is no dispatch node"));
        };
        let mut entries = BTreeSet::new();
        for edge in &node.sites {
            match reducible.node(edge.to).kind {
                NodeKind::Block(entry) if entries.insert(entry) => {}
                _ => return reject(format!("dispatch node {index} goes to no block, or twice")),
            }
        }
        if entries.first() != Some(&addr) {
            return reject(format!(
                "dispatch node {index} is not named by its lowest entry"
            ));
        }
        // Sites from dispatch nodes record no state, so the ones that chose these entries are all
        // among the original nodes, counted above, and some site of the cycle reaches its entries.
        if chosen.get(&index) != Some(&entries) {
            return reject(format!(
                "dispatch node {index} goes to entries its sites do not choose"
            ));
        }
    }
    Ok(())
}

/// What encloses a piece of code: a loop, by its header, or a labeled block, by the node after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Label {
    Loop(NodeId),
    Block(NodeId),
}

/// A step of the walk over the arena.
enum Step {
    /// Check a shape.
    Enter(ShapeId),
    /// Leave the innermost loop or labeled block.
    Leave,
}

/// The shapes against the graph they are the form of.
fn check_shapes(graph: &Graph, structure: &Structure) -> Result<(), Rejected> {
    let count = graph.nodes().len();
    let order = Order::new(graph);
    let dominators = Dominators::new(graph, &order);
    let mut forward = vec![0usize; count];
    for (from, node) in graph.nodes().iter().enumerate() {
        for edge in &node.sites {
            if !order.is_back(from, edge.to) {
                forward[edge.to] += 1;
            }
        }
    }
    let shapes = &structure.shapes;
    let get = |id: ShapeId| match shapes.get(id) {
        Some(shape) => Ok(shape),
        None => reject(format!("no shape {id}")),
    };
    let mut seen_shapes = vec![false; shapes.len()];
    let mut seen_nodes = vec![false; count];
    let mut labels: BTreeSet<Label> = BTreeSet::new();
    let mut scope: Vec<Label> = Vec::new();
    let mut steps = vec![Step::Enter(structure.root)];
    if first_node(structure, structure.root)? != order.nodes()[0] {
        return reject("the form does not start with the entry");
    }
    while let Some(step) = steps.pop() {
        let id = match step {
            Step::Enter(id) => id,
            Step::Leave => {
                scope.pop();
                continue;
            }
        };
        if std::mem::replace(&mut seen_shapes[id], true) {
            return reject(format!("shape {id} appears twice"));
        }
        match *get(id)? {
            Shape::Loop { header, body } => {
                if first_node(structure, body)? != header {
                    return reject(format!("the loop of node {header} does not start with it"));
                }
                if !labels.insert(Label::Loop(header)) {
                    return reject(format!("two loops of node {header}"));
                }
                scope.push(Label::Loop(header));
                steps.extend([Step::Leave, Step::Enter(body)]);
            }
            Shape::Labeled { follow, body, then } => {
                if first_node(structure, then)? != follow {
                    return reject(format!(
                        "the block before node {follow} is not followed by it"
                    ));
                }
                if !labels.insert(Label::Block(follow)) {
                    return reject(format!("two blocks before node {follow}"));
                }
                scope.push(Label::Block(follow));
                steps.extend([Step::Enter(then), Step::Leave, Step::Enter(body)]);
            }
            Shape::Code { node, ref sites } => {
                if node >= count || std::mem::replace(&mut seen_nodes[node], true) {
                    return reject(format!("node {node} is written twice, or is no node"));
                }
                let edges = &graph.node(node).sites;
                if sites.len() != edges.len() {
                    return reject(format!(
                        "node {node}: {} branches for {} sites",
                        sites.len(),
                        edges.len()
                    ));
                }
                for (site, (&branch, edge)) in sites.iter().zip(edges).enumerate() {
                    let at = || format!("node {node}, site {site}");
                    if branch.to() != edge.to || branch.state() != edge.state {
                        return reject(format!("{}: not the site of the graph", at()));
                    }
                    let back = order.is_back(node, edge.to);
                    match branch {
                        Branch::Continue { to, .. } => {
                            if !back || !scope.contains(&Label::Loop(to)) {
                                return reject(format!(
                                    "{}: continue to node {to}, which is not a loop around a \
                                     site that goes back",
                                    at()
                                ));
                            }
                        }
                        Branch::Break { to, .. } => {
                            if back || !scope.contains(&Label::Block(to)) {
                                return reject(format!(
                                    "{}: break to node {to}, which no block around it precedes",
                                    at()
                                ));
                            }
                        }
                        Branch::Inline { to, code, .. } => {
                            if back || forward[to] != 1 || dominators.idom(to) != node {
                                return reject(format!(
                                    "{}: node {to} written in place, which another site reaches \
                                     or this node does not dominate",
                                    at()
                                ));
                            }
                            if first_node(structure, code)? != to {
                                return reject(format!(
                                    "{}: the code in place does not start with node {to}",
                                    at()
                                ));
                            }
                            steps.push(Step::Enter(code));
                        }
                    }
                }
            }
        }
    }
    if let Some(node) = seen_nodes.iter().position(|&seen| !seen) {
        return reject(format!("node {node} is not written"));
    }
    if let Some(id) = seen_shapes.iter().position(|&seen| !seen) {
        return reject(format!("shape {id} is not part of the form"));
    }
    Ok(())
}

/// The node whose code a shape starts with.
fn first_node(structure: &Structure, mut id: ShapeId) -> Result<NodeId, Rejected> {
    // A chain of bodies longer than the arena would be a cycle in it.
    for _ in 0..=structure.shapes.len() {
        match structure.shapes.get(id) {
            Some(Shape::Code { node, .. }) => return Ok(*node),
            Some(Shape::Loop { body, .. } | Shape::Labeled { body, .. }) => id = *body,
            None => return reject(format!("no shape {id}")),
        }
    }
    reject("the bodies of the form go round in a cycle")
}
