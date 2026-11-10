// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

mod support;

use std::collections::{BTreeSet, VecDeque};

use super::*;
use support::{Rng, addr, dominator_sets, interpret, random_blocks, walk};

/// The graph of blocks `0..`, at the addresses of [`addr`], whose sites go to the blocks of
/// `sites[i]`.
fn graph(sites: &[&[usize]]) -> Graph {
    let blocks: Vec<(u32, Vec<u32>)> = sites
        .iter()
        .enumerate()
        .map(|(index, targets)| (addr(index), targets.iter().map(|&t| addr(t)).collect()))
        .collect();
    Graph::from_blocks(&blocks)
}

/// The nodes of `graph` in its order.
fn order_of(graph: &Graph) -> Vec<NodeId> {
    Order::new(graph).nodes().to_vec()
}

fn edge(to: NodeId) -> Edge {
    Edge { to, state: None }
}

#[test]
fn a_graph_leaves_out_what_the_entry_does_not_reach() {
    // Block 2 goes to block 1, but nothing goes to block 2.
    let graph = graph(&[&[1], &[], &[1]]);
    assert_eq!(
        graph.nodes(),
        [
            Node {
                kind: NodeKind::Block(addr(0)),
                sites: vec![edge(1)],
            },
            Node {
                kind: NodeKind::Block(addr(1)),
                sites: vec![],
            },
        ]
    );
    assert_eq!(graph.node_of(addr(1)), Some(1));
    assert_eq!(graph.node_of(addr(2)), None);
}

#[test]
fn renumbering_keeps_the_sites_on_their_blocks() {
    // Block 1 is unreachable, so block 2 becomes node 1; both sites of block 0 go to it.
    let graph = graph(&[&[2, 2], &[0], &[0]]);
    assert_eq!(graph.node(0).sites, [edge(1), edge(1)]);
    assert_eq!(graph.node(1).kind, NodeKind::Block(addr(2)));
    assert_eq!(graph.predecessors(), [vec![1], vec![0, 0]]);
}

#[test]
#[should_panic(expected = "where no block starts")]
fn a_site_to_no_block_is_a_bug_of_the_caller() {
    Graph::from_blocks(&[(addr(0), vec![addr(0) + 4])]);
}

#[test]
fn the_order_follows_the_addresses_where_the_branches_allow() {
    // A diamond whose taken side, block 2, comes first among the sites of block 0.
    assert_eq!(order_of(&graph(&[&[2, 1], &[3], &[3], &[]])), [0, 1, 2, 3]);
    // A loop at block 1 with its exit at block 2.
    assert_eq!(order_of(&graph(&[&[1], &[1, 2], &[]])), [0, 1, 2]);
    // Block 1 is reached only from block 2, a later address, so it comes after it.
    assert_eq!(order_of(&graph(&[&[2], &[3], &[1], &[]])), [0, 2, 1, 3]);
}

#[test]
fn back_sites_go_to_a_node_no_later_in_the_order() {
    let graph = graph(&[&[1], &[1, 2], &[0]]);
    let order = Order::new(&graph);
    assert!(!order.is_back(0, 1));
    assert!(order.is_back(1, 1));
    assert!(!order.is_back(1, 2));
    assert!(order.is_back(2, 0));
}

/// Whether some path goes from `from` to `to`.
fn reaches(graph: &Graph, from: NodeId, to: NodeId) -> bool {
    let mut seen = BTreeSet::from([from]);
    let mut queue = VecDeque::from([from]);
    while let Some(node) = queue.pop_front() {
        if node == to {
            return true;
        }
        for edge in &graph.node(node).sites {
            if seen.insert(edge.to) {
                queue.push_back(edge.to);
            }
        }
    }
    false
}

#[test]
fn the_order_is_a_reverse_postorder_on_random_graphs() {
    let mut rng = Rng::new(1);
    for case in 0..2000 {
        let count = 1 + rng.below(12);
        let graph = Graph::from_blocks(&random_blocks(&mut rng, count, 3));
        let order = Order::new(&graph);
        let mut nodes = order.nodes().to_vec();
        assert_eq!(nodes[0], 0, "case {case}");
        nodes.sort_unstable();
        assert_eq!(
            nodes,
            (0..graph.nodes().len()).collect::<Vec<_>>(),
            "case {case}"
        );
        // A site that goes back goes to a node of the walk's path, which reaches its source.
        for (from, node) in graph.nodes().iter().enumerate() {
            for edge in &node.sites {
                if order.is_back(from, edge.to) {
                    assert!(reaches(&graph, edge.to, from), "case {case}: {graph:?}");
                }
            }
        }
    }
}

#[test]
fn dominators_of_a_diamond_a_loop_and_two_entries() {
    let dominators = |sites: &[&[usize]]| {
        let graph = graph(sites);
        let dominators = Dominators::new(&graph, &Order::new(&graph));
        (0..graph.nodes().len())
            .map(|node| dominators.idom(node))
            .collect::<Vec<_>>()
    };
    assert_eq!(dominators(&[&[2, 1], &[3], &[3], &[]]), [0, 0, 0, 0]);
    assert_eq!(dominators(&[&[1], &[1, 2], &[]]), [0, 0, 1]);
    // Blocks 1 and 2 form a cycle that the entry enters at both: neither dominates the other.
    assert_eq!(dominators(&[&[1, 2], &[2, 3], &[1], &[]]), [0, 0, 0, 1]);
}

#[test]
fn dominators_agree_with_their_definition_on_random_graphs() {
    let mut rng = Rng::new(2);
    for case in 0..2000 {
        let count = 1 + rng.below(14);
        let graph = Graph::from_blocks(&random_blocks(&mut rng, count, 3));
        let dominators = Dominators::new(&graph, &Order::new(&graph));
        for (node, set) in dominator_sets(&graph).iter().enumerate() {
            let fast: BTreeSet<NodeId> = (0..graph.nodes().len())
                .filter(|&other| dominators.dominates(other, node))
                .collect();
            assert_eq!(&fast, set, "case {case}, node {node}: {graph:?}");
        }
    }
}

/// The structured form of `sub_822efaa8` of a game, by hand: block 0 tests and goes to block 3 or
/// on to block 1, which goes into the loop at block 2; the loop goes back or to block 3, which
/// leaves. Block 3 follows a labeled block around the rest.
fn loop_function() -> (Graph, Structure) {
    let graph = graph(&[&[3, 1], &[2], &[2, 3], &[]]);
    let shapes = vec![
        // 0: 'b3: { code 0 } then code 3
        Shape::Labeled {
            follow: 3,
            body: 1,
            then: 5,
        },
        // 1: code 0: break 'b3, or code 1 in place
        Shape::Code {
            node: 0,
            sites: vec![
                Branch::Break { to: 3, state: None },
                Branch::Inline {
                    to: 1,
                    state: None,
                    code: 2,
                },
            ],
        },
        // 2: code 1: into the loop at block 2
        Shape::Code {
            node: 1,
            sites: vec![Branch::Inline {
                to: 2,
                state: None,
                code: 3,
            }],
        },
        // 3: 'l2: loop { code 2 }
        Shape::Loop { header: 2, body: 4 },
        // 4: code 2: continue 'l2, or break 'b3
        Shape::Code {
            node: 2,
            sites: vec![
                Branch::Continue { to: 2, state: None },
                Branch::Break { to: 3, state: None },
            ],
        },
        // 5: code 3
        Shape::Code {
            node: 3,
            sites: vec![],
        },
    ];
    (graph, Structure { shapes, root: 0 })
}

#[test]
fn a_structured_form_runs_as_its_graph() {
    let (graph, structure) = loop_function();
    let mut lengths = BTreeSet::new();
    for seed in 0..500 {
        let expected = walk(&graph, seed, 64).unwrap();
        assert_eq!(
            interpret(&graph, &structure, seed, 64),
            Ok(expected.clone())
        );
        lengths.insert(expected.len());
    }
    // The seeds take every way through: leaving at once, and the loop run several times.
    assert!(lengths.contains(&1), "{lengths:?}");
    assert!(
        lengths.last().is_some_and(|&longest| longest >= 8),
        "{lengths:?}"
    );
}

#[test]
fn a_wrong_structured_form_runs_otherwise_or_not_at_all() {
    let (graph, structure) = loop_function();
    let differs = |structure: &Structure| {
        (0..500).any(|seed| interpret(&graph, structure, seed, 64) != walk(&graph, seed, 64))
    };
    assert!(!differs(&structure));
    // The loop's two branches swapped: they no longer stand for the sites of their node.
    let mut swapped = structure.clone();
    swapped.shapes[4] = Shape::Code {
        node: 2,
        sites: vec![
            Branch::Break { to: 3, state: None },
            Branch::Continue { to: 2, state: None },
        ],
    };
    assert!(differs(&swapped));
    // A `continue` to a node that heads no loop around the site.
    let mut outside = structure.clone();
    outside.shapes[1] = Shape::Code {
        node: 0,
        sites: vec![
            Branch::Continue { to: 3, state: None },
            Branch::Inline {
                to: 1,
                state: None,
                code: 2,
            },
        ],
    };
    assert!((0..500).any(|seed| {
        interpret(&graph, &outside, seed, 64).is_err_and(|e| e.contains("outside its loop"))
    }));
}

/// Blocks 1 and 2 form a cycle that block 0 enters at both.
fn two_entries() -> Graph {
    graph(&[&[1, 2], &[2, 3], &[1], &[]])
}

/// [`two_entries`] with dispatch node 4 in front of its cycle, by hand. Block 0 reaches it through
/// two sites, which choose blocks 1 and 2; the cycle's sites into its entries go through it too.
fn two_entries_redirected() -> Graph {
    let to_dispatch = |entry: usize| Edge {
        to: 4,
        state: Some(addr(entry)),
    };
    Graph::from_nodes(vec![
        Node {
            kind: NodeKind::Block(addr(0)),
            sites: vec![to_dispatch(1), to_dispatch(2)],
        },
        Node {
            kind: NodeKind::Block(addr(1)),
            sites: vec![to_dispatch(2), edge(3)],
        },
        Node {
            kind: NodeKind::Block(addr(2)),
            sites: vec![to_dispatch(1)],
        },
        Node {
            kind: NodeKind::Block(addr(3)),
            sites: vec![],
        },
        Node {
            kind: NodeKind::Dispatch(addr(1)),
            sites: vec![edge(1), edge(2)],
        },
    ])
}

/// Whether runs of `changed` and of `original` visit the same blocks on `seeds` seeds.
fn runs_alike(changed: &Graph, original: &Graph, seeds: u64) -> bool {
    (0..seeds).all(|seed| walk(changed, seed, 64) == walk(original, seed, 64))
}

#[test]
fn a_dispatch_node_goes_to_the_entry_its_state_names() {
    let redirected = two_entries_redirected();
    assert!(runs_alike(&redirected, &two_entries(), 500));
    // A wrong state sends the walk elsewhere.
    let mut wrong = redirected.nodes().to_vec();
    wrong[2].sites[0].state = Some(addr(2));
    assert!(!runs_alike(&Graph::from_nodes(wrong), &two_entries(), 500));
}

#[test]
fn a_reducible_graph_comes_back_unchanged() {
    let graphs: [&[&[usize]]; 4] = [
        &[&[2, 1], &[3], &[3], &[]],
        &[&[1], &[1, 2], &[]],
        // Two loops, one inside the other, and a site to the next block from both sides.
        &[&[1], &[2, 2], &[2, 3], &[1, 4], &[]],
        &[&[0, 1], &[]],
    ];
    for sites in graphs {
        let graph = graph(sites);
        assert!(is_reducible(&graph), "{graph:?}");
        let reducible = make_reducible(&graph);
        assert_eq!(reducible.graph, graph);
        assert_eq!(
            (reducible.dispatch_nodes, reducible.redirected_sites),
            (0, 0)
        );
    }
}

#[test]
fn a_cycle_with_two_entries_gets_a_dispatch_node() {
    assert!(!is_reducible(&two_entries()));
    let reducible = make_reducible(&two_entries());
    assert_eq!(reducible.graph, two_entries_redirected());
    assert_eq!(
        (reducible.dispatch_nodes, reducible.redirected_sites),
        (1, 4)
    );
    assert!(is_reducible(&reducible.graph));
}

#[test]
fn a_cycle_with_three_entries_gets_one_dispatch_node() {
    // Block 0 enters the cycle 1 -> 2 -> 3 -> 1 at each of its blocks; block 3 leaves to block 4.
    let original = graph(&[&[1, 2, 3], &[2], &[3], &[1, 4], &[]]);
    let reducible = make_reducible(&original);
    assert_eq!(
        (reducible.dispatch_nodes, reducible.redirected_sites),
        (1, 6)
    );
    let dispatch = reducible.graph.node(5);
    assert_eq!(dispatch.kind, NodeKind::Dispatch(addr(1)));
    assert_eq!(dispatch.sites, [edge(1), edge(2), edge(3)]);
    assert_eq!(reducible.graph.node(3).sites[1], edge(4));
    assert!(is_reducible(&reducible.graph));
    assert!(runs_alike(&reducible.graph, &original, 500));
}

#[test]
fn a_cycle_with_two_entries_inside_a_loop_gets_a_dispatch_node_inside_the_loop() {
    // The loop at block 1 holds the cycle 2 <-> 3, which block 1 enters at both blocks; block 4
    // goes back to the loop's top or leaves.
    let original = graph(&[&[1], &[2, 3], &[3, 4], &[2, 4], &[1, 5], &[]]);
    let reducible = make_reducible(&original);
    assert_eq!(
        (reducible.dispatch_nodes, reducible.redirected_sites),
        (1, 4)
    );
    assert_eq!(reducible.graph.node(6).kind, NodeKind::Dispatch(addr(2)));
    // The loop's back site still goes to its top.
    assert_eq!(reducible.graph.node(4).sites, [edge(1), edge(5)]);
    assert!(is_reducible(&reducible.graph));
    assert!(runs_alike(&reducible.graph, &original, 500));
}

#[test]
fn random_graphs_become_reducible_and_run_as_before() {
    let mut rng = Rng::new(3);
    let mut irreducible = 0;
    for case in 0..3000 {
        let count = 1 + rng.below(12);
        let original = Graph::from_blocks(&random_blocks(&mut rng, count, 3));
        let reducible = make_reducible(&original);
        assert!(is_reducible(&reducible.graph), "case {case}: {original:?}");
        if is_reducible(&original) {
            assert_eq!(reducible.graph, original, "case {case}");
        } else {
            irreducible += 1;
            assert!(reducible.dispatch_nodes > 0, "case {case}");
        }
        // The blocks keep their indices; only dispatch nodes come after them.
        for (index, node) in original.nodes().iter().enumerate() {
            assert_eq!(reducible.graph.node(index).kind, node.kind, "case {case}");
        }
        assert!(
            runs_alike(&reducible.graph, &original, 40),
            "case {case}: {original:?}"
        );
    }
    // The cases exercise the dispatch nodes, not only graphs that need none: with this seed, 274
    // of them need one.
    assert!(irreducible >= 200, "{irreducible}");
}

/// The structured form as text: a labeled block as `b<node> {`, a loop as `l<node> loop {`, and the
/// code of a node as `<node>:` with its branches, the code written in place below it. A state shows
/// as `=<node>`, the node of the entry it chooses.
fn render(structured: &Structured) -> String {
    fn shape(structured: &Structured, id: ShapeId, depth: usize, out: &mut Vec<String>) {
        let indent = "  ".repeat(depth);
        match &structured.structure.shapes[id] {
            Shape::Labeled { follow, body, then } => {
                out.push(format!("{indent}b{follow} {{"));
                shape(structured, *body, depth + 1, out);
                out.push(format!("{indent}}}"));
                shape(structured, *then, depth, out);
            }
            Shape::Loop { header, body } => {
                out.push(format!("{indent}l{header} loop {{"));
                shape(structured, *body, depth + 1, out);
                out.push(format!("{indent}}}"));
            }
            Shape::Code { node, sites } => {
                let state = |branch: &Branch| match branch.state() {
                    Some(entry) => format!(" ={}", structured.graph.node_of(entry).unwrap()),
                    None => String::new(),
                };
                let branches: Vec<String> = sites
                    .iter()
                    .map(|branch| match branch {
                        Branch::Continue { to, .. } => format!("continue l{to}{}", state(branch)),
                        Branch::Break { to, .. } => format!("break b{to}{}", state(branch)),
                        Branch::Inline { to, .. } => format!("inline {to}{}", state(branch)),
                    })
                    .collect();
                let separator = if branches.is_empty() { "" } else { " " };
                out.push(format!("{indent}{node}:{separator}{}", branches.join(", ")));
                for branch in sites {
                    if let Branch::Inline { code, .. } = branch {
                        shape(structured, *code, depth + 1, out);
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    shape(structured, structured.structure.root, 0, &mut out);
    out.join("\n")
}

/// The structured form of `sites`, as [`render`] writes it.
fn structured_text(sites: &[&[usize]]) -> String {
    render(&structure(&graph(sites)).unwrap())
}

#[test]
fn a_loop_with_an_exit_shared_by_its_entry_test() {
    // sub_822efaa8 of a game, as in `loop_function`.
    assert_eq!(
        structured_text(&[&[3, 1], &[2], &[2, 3], &[]]),
        [
            "b3 {",
            "  0: break b3, inline 1",
            "    1: inline 2",
            "      l2 loop {",
            "        2: continue l2, break b3",
            "      }",
            "}",
            "3:",
        ]
        .join("\n")
    );
}

#[test]
fn a_diamond_writes_both_sides_in_place_and_breaks_to_the_join() {
    assert_eq!(
        structured_text(&[&[2, 1], &[3], &[3], &[]]),
        [
            "b3 {",
            "  0: inline 2, inline 1",
            "    2: break b3",
            "    1: break b3",
            "}",
            "3:",
        ]
        .join("\n")
    );
}

#[test]
fn a_branch_whose_sides_meet_writes_the_block_once() {
    // Both sites of block 0 go to block 1: two sites, so block 1 is a merge node.
    assert_eq!(
        structured_text(&[&[1, 1], &[]]),
        ["b1 {", "  0: break b1, break b1", "}", "1:"].join("\n")
    );
}

#[test]
fn nested_loops_continue_either_and_leave_both() {
    assert_eq!(
        structured_text(&[&[1], &[2], &[2, 1, 3], &[]]),
        [
            "0: inline 1",
            "  l1 loop {",
            "    1: inline 2",
            "      l2 loop {",
            "        2: continue l2, continue l1, inline 3",
            "          3:",
            "      }",
            "  }",
        ]
        .join("\n")
    );
}

#[test]
fn a_cycle_with_two_entries_loops_through_its_dispatch_node() {
    // Node 4 is the dispatch node: block 0 breaks to it with the entry it chooses, and the cycle
    // continues it with the next entry.
    assert_eq!(
        render(&structure(&two_entries()).unwrap()),
        [
            "b4 {",
            "  0: break b4 =1, break b4 =2",
            "}",
            "l4 loop {",
            "  4: inline 1, inline 2",
            "    1: continue l4 =2, inline 3",
            "      3:",
            "    2: continue l4 =1",
            "}",
        ]
        .join("\n")
    );
}

#[test]
fn the_entry_can_head_a_loop() {
    assert_eq!(
        structured_text(&[&[0, 1], &[]]),
        ["l0 loop {", "  0: continue l0, inline 1", "    1:", "}"].join("\n")
    );
}

/// The code shape of `node` in `structure`.
fn code_of(structure: &Structure, node: NodeId) -> ShapeId {
    structure
        .shapes
        .iter()
        .position(|shape| matches!(shape, Shape::Code { node: n, .. } if *n == node))
        .unwrap()
}

/// Why `verify` rejects `structure` as the form of `structured`'s graph, `original` with dispatch
/// nodes, or `None` if it accepts it.
fn why(original: &Graph, structured: &Structured, structure: &Structure) -> Option<String> {
    verify(original, &structured.graph, structure)
        .err()
        .map(|rejected| rejected.0)
}

#[test]
fn the_check_rejects_forms_that_would_run_otherwise() {
    let diamond = graph(&[&[2, 1], &[3], &[3], &[]]);
    let structured = structure(&diamond).unwrap();
    let good = &structured.structure;
    assert_eq!(why(&diamond, &structured, good), None);
    let with_sites = |node: NodeId, sites: Vec<Branch>| {
        let mut changed = good.clone();
        let id = code_of(&changed, node);
        changed.shapes[id] = Shape::Code { node, sites };
        changed
    };
    // The join written in place at one of its two sites, as well as after the block.
    let mut twice = with_sites(
        2,
        vec![Branch::Inline {
            to: 3,
            state: None,
            code: good.shapes.len(),
        }],
    );
    twice.shapes.push(Shape::Code {
        node: 3,
        sites: vec![],
    });
    let reason = why(&diamond, &structured, &twice).unwrap();
    assert!(reason.contains("node 3"), "{reason}");
    // A `continue` on a site that goes forward.
    let forward = with_sites(1, vec![Branch::Continue { to: 3, state: None }]);
    let reason = why(&diamond, &structured, &forward).unwrap();
    assert!(reason.contains("continue to node 3"), "{reason}");
    // A shape that nothing refers to.
    let mut spare = good.clone();
    spare.shapes.push(Shape::Code {
        node: 3,
        sites: vec![],
    });
    let reason = why(&diamond, &structured, &spare).unwrap();
    assert!(reason.contains("not part of the form"), "{reason}");
    // A `break` with no block before its node around it.
    let nested = graph(&[&[1], &[2], &[2, 1, 3], &[]]);
    let loops = structure(&nested).unwrap();
    let mut outside = loops.structure.clone();
    let id = code_of(&outside, 2);
    if let Shape::Code { sites, .. } = &mut outside.shapes[id] {
        sites[2] = Branch::Break { to: 3, state: None };
    }
    let reason = why(&nested, &loops, &outside).unwrap();
    assert!(reason.contains("break to node 3"), "{reason}");
    // A loop that does not start with its header.
    let mut header = loops.structure.clone();
    for shape in &mut header.shapes {
        if let Shape::Loop { header: node, .. } = shape
            && *node == 2
        {
            *node = 3;
        }
    }
    let reason = why(&nested, &loops, &header).unwrap();
    assert!(reason.contains("does not start with it"), "{reason}");
}

#[test]
fn the_check_holds_dispatch_nodes_to_the_original_graph() {
    let original = two_entries();
    let structured = structure(&original).unwrap();
    assert_eq!(
        verify(&original, &structured.graph, &structured.structure),
        Ok(())
    );
    // A redirected site that records the other entry.
    let mut nodes = structured.graph.nodes().to_vec();
    nodes[2].sites[0].state = Some(addr(2));
    let reason = verify(&original, &Graph::from_nodes(nodes), &structured.structure)
        .unwrap_err()
        .0;
    assert!(reason.contains("records"), "{reason}");
    // The original graph passed as if it were reducible.
    let reason = verify(&original, &original, &structured.structure)
        .unwrap_err()
        .0;
    assert!(reason.contains("not reducible"), "{reason}");
}

#[test]
fn random_graphs_structure_and_run_as_before() {
    let mut rng = Rng::new(4);
    for case in 0..3000 {
        let count = 1 + rng.below(12);
        let original = Graph::from_blocks(&random_blocks(&mut rng, count, 3));
        let structured = match structure(&original) {
            Ok(structured) => structured,
            Err(rejected) => panic!("case {case}: {rejected}: {original:?}"),
        };
        for seed in 0..40 {
            assert_eq!(
                interpret(&structured.graph, &structured.structure, seed, 64),
                walk(&original, seed, 64),
                "case {case}, seed {seed}: {original:?}\n{}",
                render(&structured)
            );
        }
    }
}

#[test]
fn larger_random_graphs_structure_and_run_as_before() {
    let mut rng = Rng::new(5);
    for case in 0..200 {
        let count = 20 + rng.below(80);
        let original = Graph::from_blocks(&random_blocks(&mut rng, count, 3));
        let structured = match structure(&original) {
            Ok(structured) => structured,
            Err(rejected) => panic!("case {case}: {rejected}"),
        };
        for seed in 0..20 {
            assert_eq!(
                interpret(&structured.graph, &structured.structure, seed, 256),
                walk(&original, seed, 256),
                "case {case}, seed {seed}"
            );
        }
    }
}

#[test]
fn merge_children_nest_with_the_latest_outermost() {
    // Blocks 3 and 4 both join paths of block 0's two sides, and block 3 goes on to block 4: the
    // block before 3 has to sit inside the block before 4, so that 3 can break to 4.
    assert_eq!(
        structured_text(&[&[1, 2], &[3, 4], &[3, 4], &[4], &[]]),
        [
            "b4 {",
            "  b3 {",
            "    0: inline 1, inline 2",
            "      1: break b3, break b4",
            "      2: break b3, break b4",
            "  }",
            "  3: break b4",
            "}",
            "4:",
        ]
        .join("\n")
    );
}
