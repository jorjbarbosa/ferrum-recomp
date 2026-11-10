// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Making a graph reducible: a dispatch node in front of every cycle that more than one of its
//! nodes enters.
//!
//! The structured form has loops with a single top: a cycle that control can enter at two of its
//! nodes, as code with a `goto` into a loop makes, has none. Each such cycle gets a dispatch node.
//! Every site that goes to one of the cycle's entries, from outside the cycle or from inside it,
//! goes to the dispatch node instead and records which entry it chose; the dispatch node goes on
//! to that entry. The dispatch node is then the single top of the cycle. This is the technique of
//! LLVM's `lib/Target/WebAssembly/WebAssemblyFixIrreducibleControlFlow.cpp`, read for what it does.
//!
//! The cycles are found as strongly connected components, level by level of the loop nesting: in
//! the whole graph first, then inside each cycle without the sites that go back to its top, which
//! uncovers the cycles nested in it. A cycle entered at one node only is a loop already, and the
//! search goes on inside it. After a dispatch node is added, every entry of its cycle is reached
//! from the dispatch node only, so no cycle inside goes through an entry, and every level searches
//! fewer nodes than the one before.

use super::dominators::Dominators;
use super::graph::{Edge, Graph, Node, NodeId, NodeKind, Order};

/// A graph made reducible, and what it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reducible {
    /// The graph: the nodes of the original with the same indices, then the dispatch nodes.
    pub graph: Graph,
    /// How many dispatch nodes were added: one per cycle with several entries.
    pub dispatch_nodes: usize,
    /// How many sites go to a dispatch node instead of one of its entries.
    pub redirected_sites: usize,
}

/// `graph` with a dispatch node in front of every cycle that more than one of its nodes enters.
/// A graph that is reducible already comes back unchanged.
pub fn make_reducible(graph: &Graph) -> Reducible {
    let mut nodes = graph.nodes().to_vec();
    let mut dispatch_nodes = 0;
    let mut redirected_sites = 0;
    // Each region is a set of nodes to search for cycles, and the top of the loop it is, whose
    // incoming sites the search leaves out. The first region is the whole graph.
    let mut regions: Vec<(Vec<NodeId>, Option<NodeId>)> = vec![((0..nodes.len()).collect(), None)];
    while let Some((members, top)) = regions.pop() {
        let mut inner = Vec::new();
        for cycle in cycles(&nodes, &members, top) {
            let entries = entries(&nodes, &cycle);
            if let [entry] = entries[..] {
                inner.push((cycle, Some(entry)));
                continue;
            }
            let dispatch = nodes.len();
            // The address of each entry, which a site that chooses it records, lowest first.
            let addresses: Vec<(NodeId, u32)> = entries
                .iter()
                .map(|&entry| (entry, nodes[entry].kind.addr()))
                .collect();
            for node in &mut nodes {
                for edge in &mut node.sites {
                    if let Some(&(_, addr)) = addresses.iter().find(|&&(e, _)| e == edge.to) {
                        *edge = Edge {
                            to: dispatch,
                            state: Some(addr),
                        };
                        redirected_sites += 1;
                    }
                }
            }
            nodes.push(Node {
                kind: NodeKind::Dispatch(addresses[0].1),
                sites: entries.iter().map(|&to| Edge { to, state: None }).collect(),
            });
            dispatch_nodes += 1;
            // Each dispatch node stands for a cycle of two blocks or more, inside the cycle of an
            // earlier one or apart from it, and such cycles are fewer than the blocks. More
            // dispatch nodes mean that the search is not getting smaller: a bug, which would
            // otherwise add dispatch nodes for ever.
            assert!(
                dispatch_nodes < graph.nodes().len(),
                "dispatch nodes do not converge on a graph of {} nodes",
                graph.nodes().len()
            );
            let mut members = cycle;
            members.push(dispatch);
            inner.push((members, Some(dispatch)));
        }
        // Popped last, searched first: the regions are searched in the order they were found.
        regions.extend(inner.into_iter().rev());
    }
    Reducible {
        graph: Graph::from_nodes(nodes),
        dispatch_nodes,
        redirected_sites,
    }
}

/// Whether every site that goes back in the order of `graph` goes to a node that dominates its
/// source: whether every cycle has a single top, so that it can be a loop.
pub fn is_reducible(graph: &Graph) -> bool {
    let order = Order::new(graph);
    let dominators = Dominators::new(graph, &order);
    graph.nodes().iter().enumerate().all(|(from, node)| {
        node.sites
            .iter()
            .all(|edge| !order.is_back(from, edge.to) || dominators.dominates(edge.to, from))
    })
}

/// The cycles among `members`, leaving out the sites that go to `top`: the strongly connected
/// components of more than one node, or of one node with a site to itself. Each holds its nodes
/// in increasing order, and they come in the order of their first nodes.
///
/// The components come from Tarjan's algorithm ("Depth-First Search and Linear Graph Algorithms",
/// SIAM Journal on Computing, 1972), with a stack of its own in place of recursion.
fn cycles(nodes: &[Node], members: &[NodeId], top: Option<NodeId>) -> Vec<Vec<NodeId>> {
    let mut in_region = vec![false; nodes.len()];
    for &member in members {
        in_region[member] = true;
    }
    let follows = |to: NodeId| in_region[to] && Some(to) != top;
    let mut index: Vec<Option<usize>> = vec![None; nodes.len()];
    let mut low = vec![0; nodes.len()];
    let mut on_stack = vec![false; nodes.len()];
    let mut stack = Vec::new();
    let mut next = 0;
    let mut found = Vec::new();
    for &root in members {
        if index[root].is_some() {
            continue;
        }
        // Each frame is a node of the walk and how many of its sites it has looked at.
        let mut walk = vec![(root, 0)];
        index[root] = Some(next);
        low[root] = next;
        next += 1;
        stack.push(root);
        on_stack[root] = true;
        while let Some(frame) = walk.last_mut() {
            let (node, site) = *frame;
            if let Some(edge) = nodes[node].sites.get(site) {
                frame.1 += 1;
                let to = edge.to;
                if !follows(to) {
                    continue;
                }
                match index[to] {
                    None => {
                        index[to] = Some(next);
                        low[to] = next;
                        next += 1;
                        stack.push(to);
                        on_stack[to] = true;
                        walk.push((to, 0));
                    }
                    Some(seen) if on_stack[to] => low[node] = low[node].min(seen),
                    Some(_) => {}
                }
                continue;
            }
            walk.pop();
            if let Some(&(parent, _)) = walk.last() {
                low[parent] = low[parent].min(low[node]);
            }
            if Some(low[node]) == index[node] {
                let mut component = Vec::new();
                loop {
                    // The node itself is on the stack, so the loop ends at it.
                    let member = stack.pop().expect("a component's node is on the stack");
                    on_stack[member] = false;
                    component.push(member);
                    if member == node {
                        break;
                    }
                }
                let cyclic = component.len() > 1
                    || nodes[node]
                        .sites
                        .iter()
                        .any(|edge| edge.to == node && follows(node));
                if cyclic {
                    component.sort_unstable();
                    found.push(component);
                }
            }
        }
    }
    found.sort_unstable_by_key(|component| component[0]);
    found
}

/// The nodes of `cycle` that control enters from outside it: those a site from another node goes
/// to, and the function's entry, node 0. They come in the order of their addresses.
fn entries(nodes: &[Node], cycle: &[NodeId]) -> Vec<NodeId> {
    let mut entered = vec![false; nodes.len()];
    entered[0] = true;
    for (from, node) in nodes.iter().enumerate() {
        if cycle.binary_search(&from).is_err() {
            for edge in &node.sites {
                entered[edge.to] = true;
            }
        }
    }
    let mut entries: Vec<NodeId> = cycle
        .iter()
        .copied()
        .filter(|&member| entered[member])
        .collect();
    entries.sort_unstable_by_key(|&entry| nodes[entry].kind.addr());
    // A node outside a cycle that holds the function's entry would reach it from the entry and be
    // reached back from it, so it would be in the cycle: the entry is the only way in.
    debug_assert!(
        !cycle.contains(&0) || entries == [0],
        "the function's entry is the only entry of its cycle"
    );
    entries
}
