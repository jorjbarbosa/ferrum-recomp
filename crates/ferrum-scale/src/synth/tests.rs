// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use ferrum_analysis::{Code, find_save_restore};
use ferrum_codegen::Program;

use super::*;

#[test]
fn a_seed_and_a_count_always_give_the_same_program() {
    let program = generate(1, 500);
    assert_eq!(program, generate(1, 500));
    assert_ne!(program.bytes(), generate(2, 500).bytes());
    // A larger count starts with the same functions, drawn from the same sequence.
    let more = generate(1, 600);
    assert_eq!(program.functions[..400], more.functions[..400]);
}

#[test]
fn functions_follow_the_routines_back_to_back() {
    let program = generate(3, 300);
    let mut next = BASE + 4 * ROUTINE_WORDS;
    for function in &program.functions {
        assert_eq!(function.addr, next);
        next = function.addr + function.size;
    }
    assert_eq!(next, BASE + 4 * program.insns.len() as u32);
    let bytes = program.bytes();
    let routines = find_save_restore(&Code::new(BASE, &bytes));
    // 18 entries of __savegprlr and 18 of __restgprlr.
    assert_eq!(routines.len(), 36);
}

#[test]
fn sizes_follow_the_model() {
    let program = generate(4, 20_000);
    let mut sizes: Vec<u32> = program.functions.iter().map(|f| f.size / 4).collect();
    sizes.sort_unstable();
    let median = sizes[sizes.len() / 2];
    let mean = program.function_insns() as f64 / sizes.len() as f64;
    assert!((11..=15).contains(&median), "median {median}");
    assert!((35.0..43.0).contains(&mean), "mean {mean}");
    assert!(sizes[0] >= 2 && sizes[sizes.len() - 1] <= 2048);
}

#[test]
fn bodies_hold_every_kind_of_step() {
    let program = generate(5, 2000);
    let count = |pred: fn(&Insn) -> bool| program.insns.iter().filter(|i| pred(i)).count();
    let calls = count(|i| matches!(i, Insn::B { lk: true, .. }));
    let jumps = count(|i| matches!(i, Insn::B { lk: false, .. }));
    let indirect = count(|i| matches!(i, Insn::Bcctr { lk: true, .. }));
    let loops = count(|i| matches!(i, Insn::Bc { bo: 16, .. }));
    let conditional = count(|i| matches!(i, Insn::Bc { bo: 4 | 12, .. }));
    let returns = count(|i| matches!(i, Insn::Bclr { bo: 4 | 12, .. }));
    let insns = program.function_insns() as usize;
    for (name, n) in [
        ("calls", calls),
        ("jumps", jumps),
        ("indirect calls", indirect),
        ("loops", loops),
        ("conditional branches", conditional),
        ("conditional returns", returns),
    ] {
        assert!(n > 0, "no {name}");
    }
    // A branch ends a block about every 6 instructions.
    let branches = calls + jumps + indirect + loops + conditional + returns;
    let per_branch = insns as f64 / branches as f64;
    assert!((4.0..8.0).contains(&per_branch), "{per_branch}");
}

#[test]
fn every_function_generates() {
    let program = generate(6, 2000);
    let bytes = program.bytes();
    let code = Code::new(BASE, &bytes);
    let routines = find_save_restore(&code);
    let text = Program::new(code, program.functions.iter().copied(), &routines)
        .generate()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(text.matches("#[inline(never)]").count(), 2000);
    assert!(!text.contains("fell off"), "every path ends in a branch");
}
