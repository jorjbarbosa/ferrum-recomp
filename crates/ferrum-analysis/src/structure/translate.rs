// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The translation of a reducible graph into its structured form, after Norman Ramsey, "Beyond
//! Relooper: Recursive Translation of Unstructured Control Flow to Structured Control Flow
//! (Functional Pearl)", ICFP 2022.
//!
//! The code of a node holds, in place, the code of the nodes it immediately dominates. A child
//! that one site reaches is written where that site is. A child that two sites or more reach from
//! before it in the order, a merge node, cannot be written at any of them: it follows a labeled
//! block wrapped around the node's code, and its sites leave the block. The merge children of a
//! node nest with the one latest in the order outermost, so each comes after every node that
//! reaches it. A node that sites go back to is a loop header, and its code and everything inside
//! it is the body of a loop, which those sites continue. A site to a node is therefore a
//! `continue` if it goes back, a `break` if the node is a merge node, and the node's code in place
//! otherwise.
//!
//! The paper writes the translation as recursive functions over the dominator tree. Here a stack of
//! tasks does the same work, each task filling one slot of the arena, because the dominator tree of
//! a long function is as deep as the function is long.

use super::dominators::Dominators;
use super::graph::{Graph, NodeId, Order};
use super::shape::{Branch, Shape, ShapeId, Structure};

/// A piece of the translation: the shape that fills one slot of the arena.
enum Task {
    /// The code of `node` and of everything it dominates: a loop around it if it is a loop header.
    Tree { node: NodeId, slot: ShapeId },
    /// The code of `node` inside the labeled blocks of the first `merges` of its merge children.
    Within {
        node: NodeId,
        merges: usize,
        slot: ShapeId,
    },
}

/// The structured form of `graph`, which has to be reducible, given its order and dominators.
pub(crate) fn translate(graph: &Graph, order: &Order, dominators: &Dominators) -> Structure {
    let count = graph.nodes().len();
    let mut forward = vec![0usize; count];
    let mut header = vec![false; count];
    for (from, node) in graph.nodes().iter().enumerate() {
        for edge in &node.sites {
            if order.is_back(from, edge.to) {
                header[edge.to] = true;
            } else {
                forward[edge.to] += 1;
            }
        }
    }
    let merge = |node: NodeId| forward[node] >= 2;
    // The merge children of each node in the dominator tree, earliest in the order first.
    let mut merges: Vec<Vec<NodeId>> = vec![Vec::new(); count];
    for &node in &order.nodes()[1..] {
        if merge(node) {
            merges[dominators.idom(node)].push(node);
        }
    }
    let mut slots: Vec<Option<Shape>> = vec![None];
    let mut tasks = vec![Task::Tree {
        node: order.nodes()[0],
        slot: 0,
    }];
    while let Some(task) = tasks.pop() {
        match task {
            Task::Tree { node, slot } => {
                let within = if header[node] {
                    let body = slots.len();
                    slots.push(None);
                    slots[slot] = Some(Shape::Loop { header: node, body });
                    body
                } else {
                    slot
                };
                tasks.push(Task::Within {
                    node,
                    merges: merges[node].len(),
                    slot: within,
                });
            }
            Task::Within {
                node,
                merges: 0,
                slot,
            } => {
                let mut sites = Vec::with_capacity(graph.node(node).sites.len());
                for edge in &graph.node(node).sites {
                    let (to, state) = (edge.to, edge.state);
                    sites.push(if order.is_back(node, to) {
                        Branch::Continue { to, state }
                    } else if merge(to) {
                        Branch::Break { to, state }
                    } else {
                        let code = slots.len();
                        slots.push(None);
                        tasks.push(Task::Tree {
                            node: to,
                            slot: code,
                        });
                        Branch::Inline { to, state, code }
                    });
                }
                slots[slot] = Some(Shape::Code { node, sites });
            }
            Task::Within {
                node,
                merges: remaining,
                slot,
            } => {
                let follow = merges[node][remaining - 1];
                let body = slots.len();
                let then = body + 1;
                slots.extend([None, None]);
                slots[slot] = Some(Shape::Labeled { follow, body, then });
                tasks.push(Task::Tree {
                    node: follow,
                    slot: then,
                });
                tasks.push(Task::Within {
                    node,
                    merges: remaining - 1,
                    slot: body,
                });
            }
        }
    }
    let shapes = slots
        .into_iter()
        // Every slot is pushed with the task that fills it, and every task runs.
        .map(|shape| shape.expect("every slot of the arena is filled"))
        .collect();
    Structure { shapes, root: 0 }
}
