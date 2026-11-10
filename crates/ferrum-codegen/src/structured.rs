// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Structured code: a function written from its structured form, with labeled blocks, loops,
//! `break`, `continue` and `if`, instead of a loop over a `match` on the address of the next block.
//!
//! The code of each block is written first on its own, as for a dispatcher, except that each site,
//! where the code sends control to another block, is a placeholder line. A walk of the structured
//! form then writes the function: a labeled block or a loop around its body; the code of a block,
//! with each placeholder replaced by the site's branch, a `break`, a `continue`, or the code of the
//! next block in place; and a dispatch node, as a `match` on its state variable.
//!
//! Every body, of the function, of a loop and of a labeled block, is
//! `let _: core::convert::Infallible = { ... };`. A body whose every path ends in a transfer has
//! no value, which Rust lets stand for any type; a body that a path could run to the end of has the
//! value `()` and does not compile. A missing transfer is a build error, never a wrong path at run
//! time. A state variable is declared without a value for the same reason: a path that reaches its
//! dispatch node without setting it does not compile.
//!
//! A conditional branch inside the function is `if condition { taken side }` with the other side
//! after it, at the same level, rather than an `if` and an `else`: a chain of tests then nests no
//! deeper than its real nesting. The taken side always ends in a transfer, so the other side runs
//! only when the condition fails. Where more code follows a site in its block, as after the taken
//! side or a hook's jump, what is written there gets the guard too, a `break` or a `continue` as
//! much as the code of a block, so that a path into the code that follows is a build error as
//! well.
//!
//! The walk keeps a stack of its own, so a deep form takes no stack of the host.

use std::collections::BTreeMap;
use std::ops::RangeInclusive;

use ferrum_analysis::{Branch, Cfg, Function, Graph, NodeId, NodeKind, Shape, ShapeId, Structured};

use crate::emit::Emitter;
use crate::error::Error;
use crate::program::{ControlFlow, Program, function_name};

/// The deepest that the braces of a structured function may nest. Measured with rustc 1.99.1, the
/// compiler's stack overflows between 600 and 800 nested labeled blocks with their guards; the
/// deepest function of the game first measured nests about 60.
pub(crate) const MAX_BRACE_DEPTH: usize = 256;

/// How deep inside a block's own code the code of a site can sit: in the arm of a jump table's
/// `match`, or in the guard inside the `if` of a conditional branch.
const SITE_DEPTH: usize = 2;

/// How deep a block's own code nests braces: a conditional call into an inlined save routine, one
/// of whose instructions opens a block of its own.
const BLOCK_DEPTH: usize = 3;

/// What starts a placeholder line, which no generated code holds.
const MARK: char = '\u{0}';

/// The guard around every body.
const GUARD: &str = "let _: core::convert::Infallible = {";

/// What marks a placeholder whose site more code of its block follows.
const FOLLOWED: char = '!';

/// The placeholder line of the site `index` of a block, which more code of the block follows if
/// `followed`.
pub(crate) fn placeholder(index: usize, followed: bool) -> String {
    if followed {
        format!("{MARK}{FOLLOWED}{index}")
    } else {
        format!("{MARK}{index}")
    }
}

/// The indent, in levels, the site index, and whether more code follows, of a placeholder line.
fn parse_placeholder(line: &str) -> Option<(usize, usize, bool)> {
    let content = line.trim_start_matches(' ');
    let rest = content.strip_prefix(MARK)?;
    let (followed, digits) = match rest.strip_prefix(FOLLOWED) {
        Some(digits) => (true, digits),
        None => (false, rest),
    };
    Some((
        (line.len() - content.len()) / 4,
        digits.parse().ok()?,
        followed,
    ))
}

/// An upper bound on how deep the braces of the structured code of `structured` nest, counting
/// those of the function itself.
pub(crate) fn brace_depth(structured: &Structured) -> usize {
    let shapes = &structured.structure.shapes;
    let mut deepest = 0;
    // The braces of the function and of the guard of its body.
    let mut stack = vec![(structured.structure.root, 2)];
    while let Some((id, depth)) = stack.pop() {
        match &shapes[id] {
            Shape::Labeled { body, then, .. } => {
                stack.push((*body, depth + 2));
                stack.push((*then, depth));
            }
            Shape::Loop { body, .. } => stack.push((*body, depth + 2)),
            Shape::Code { sites, .. } => {
                deepest = deepest.max(depth + BLOCK_DEPTH);
                for branch in sites {
                    if let Branch::Inline { code, .. } = branch {
                        stack.push((*code, depth + SITE_DEPTH));
                    }
                }
            }
        }
    }
    deepest
}

/// The label of the loop whose header is `node`.
fn loop_label(graph: &Graph, node: NodeId) -> String {
    match graph.node(node).kind {
        NodeKind::Block(addr) => format!("'l_{addr:08x}"),
        NodeKind::Dispatch(addr) => format!("'d_{addr:08x}"),
    }
}

/// The label of the labeled block that `node` follows.
fn block_label(graph: &Graph, node: NodeId) -> String {
    match graph.node(node).kind {
        NodeKind::Block(addr) => format!("'b_{addr:08x}"),
        NodeKind::Dispatch(addr) => format!("'b_d_{addr:08x}"),
    }
}

/// The state variable of the dispatch node named `addr`.
fn state(addr: u32) -> String {
    format!("state_{addr:08x}")
}

/// The text of `function`, whose blocks are `cfg` and whose structured form is `structured`,
/// calling the functions in `local` directly.
pub(crate) fn generate(
    program: &Program<'_>,
    function: Function,
    cfg: &Cfg,
    structured: &Structured,
    local: RangeInclusive<u32>,
) -> Result<String, Error> {
    let graph = &structured.graph;
    let mut e = Emitter::new(program, function, local, ControlFlow::Structured);
    let mut texts: BTreeMap<NodeId, Vec<String>> = BTreeMap::new();
    for (node, kind) in graph.nodes().iter().map(|node| node.kind).enumerate() {
        let NodeKind::Block(start) = kind else {
            continue;
        };
        let index = cfg
            .blocks
            .binary_search_by_key(&start, |block| block.start)
            // The graph was built from these blocks.
            .expect("every block of the graph is a block of the function");
        program.block(&mut e, function, cfg, &cfg.blocks[index])?;
        texts.insert(node, e.take_text().lines().map(str::to_owned).collect());
    }
    e.line("#[inline(never)]");
    e.open(format!(
        "pub fn {}(ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {{",
        function_name(function.addr)
    ));
    for node in graph.nodes() {
        if let NodeKind::Dispatch(addr) = node.kind {
            e.line(format!("let mut {}: u32;", state(addr)));
        }
    }
    e.open(GUARD);
    let deepest = assemble(&mut e, structured, &texts, 2);
    debug_assert!(
        deepest <= brace_depth(structured),
        "{}: nests {deepest} deep, over its bound",
        function_name(function.addr)
    );
    e.close("};");
    e.close("}");
    e.line("");
    e.finish()
}

/// A step of the walk that writes a structured form.
enum Work {
    /// Write a shape at a depth.
    Shape(ShapeId, usize),
    /// Write the code of the block of a code shape from one of its lines on, at a depth.
    Rest {
        code: ShapeId,
        line: usize,
        depth: usize,
    },
    /// Write a branch at a depth, whose code, if written in place, more code follows.
    Branch(Branch, usize, bool),
    /// Write a line at a depth.
    Line(&'static str, usize),
    /// Write a line made for the step at a depth.
    Text(String, usize),
}

/// Writes the structured form `structured` at `base`, with the code `texts` of its blocks, and
/// returns how deep its braces nest.
fn assemble(
    e: &mut Emitter<'_>,
    structured: &Structured,
    texts: &BTreeMap<NodeId, Vec<String>>,
    base: usize,
) -> usize {
    let graph = &structured.graph;
    let shapes = &structured.structure.shapes;
    let mut deepest = base;
    let mut work = vec![Work::Shape(structured.structure.root, base)];
    let mut write = |e: &mut Emitter<'_>, depth: usize, line: &str| {
        let indent = line.len() - line.trim_start_matches(' ').len();
        deepest = deepest.max(depth + indent / 4);
        e.line_at(depth, line);
    };
    while let Some(step) = work.pop() {
        match step {
            Work::Line(line, depth) => write(e, depth, line),
            Work::Text(line, depth) => write(e, depth, &line),
            Work::Shape(id, depth) => match &shapes[id] {
                Shape::Labeled { follow, body, then } => {
                    write(e, depth, &format!("{}: {{", block_label(graph, *follow)));
                    write(e, depth + 1, GUARD);
                    work.push(Work::Shape(*then, depth));
                    work.push(Work::Line("}", depth));
                    work.push(Work::Line("};", depth + 1));
                    work.push(Work::Shape(*body, depth + 2));
                }
                Shape::Loop { header, body } => {
                    write(
                        e,
                        depth,
                        &format!("{}: loop {{", loop_label(graph, *header)),
                    );
                    write(e, depth + 1, GUARD);
                    work.push(Work::Line("}", depth));
                    work.push(Work::Line("};", depth + 1));
                    work.push(Work::Shape(*body, depth + 2));
                }
                Shape::Code { node, sites } => match graph.node(*node).kind {
                    NodeKind::Block(_) => work.push(Work::Rest {
                        code: id,
                        line: 0,
                        depth,
                    }),
                    NodeKind::Dispatch(addr) => {
                        write(e, depth, &format!("match {} {{", state(addr)));
                        work.push(Work::Line("}", depth));
                        work.push(Work::Line("_ => unreachable!(),", depth + 1));
                        let edges = &graph.node(*node).sites;
                        for (branch, edge) in sites.iter().zip(edges).rev() {
                            let entry = graph.node(edge.to).kind.addr();
                            work.push(Work::Line("}", depth + 1));
                            work.push(Work::Branch(*branch, depth + 2, false));
                            work.push(Work::Text(format!("{entry:#010x} => {{"), depth + 1));
                        }
                    }
                },
            },
            Work::Rest { code, line, depth } => {
                let Shape::Code { node, sites } = &shapes[code] else {
                    unreachable!("only a code shape has the code of a block")
                };
                for (index, text) in texts[node].iter().enumerate().skip(line) {
                    if let Some((indent, site, followed)) = parse_placeholder(text) {
                        work.push(Work::Rest {
                            code,
                            line: index + 1,
                            depth,
                        });
                        work.push(Work::Branch(sites[site], depth + indent, followed));
                        break;
                    }
                    write(e, depth, text);
                }
            }
            Work::Branch(branch, depth, followed) => {
                let mut statements = Vec::new();
                if let Some(entry) = branch.state() {
                    let addr = graph.node(branch.to()).kind.addr();
                    statements.push(format!("{} = {entry:#010x};", state(addr)));
                }
                let transfer = match branch {
                    Branch::Continue { to, .. } => format!("continue {};", loop_label(graph, to)),
                    Branch::Break { to, .. } => format!("break {};", block_label(graph, to)),
                    Branch::Inline { .. } => String::new(),
                };
                if !transfer.is_empty() {
                    statements.push(transfer);
                    if followed {
                        // On one line, so that a guarded jump costs no depth.
                        write(e, depth, &format!("{GUARD} {} }};", statements.join(" ")));
                    } else {
                        for statement in &statements {
                            write(e, depth, statement);
                        }
                    }
                    continue;
                }
                for statement in &statements {
                    write(e, depth, statement);
                }
                match branch {
                    Branch::Continue { .. } | Branch::Break { .. } => {
                        unreachable!("a jump was written above")
                    }
                    Branch::Inline { code, .. } if followed => {
                        write(e, depth, GUARD);
                        work.push(Work::Line("};", depth));
                        work.push(Work::Shape(code, depth + 1));
                    }
                    Branch::Inline { code, .. } => work.push(Work::Shape(code, depth)),
                }
            }
        }
    }
    deepest
}
