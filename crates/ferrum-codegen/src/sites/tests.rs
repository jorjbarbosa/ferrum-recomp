// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use ferrum_analysis::{Code, Function, SaveRestore};
use ferrum_decoder::{CrBit, Insn};

use super::*;
use crate::tests::{BASE, assemble, b, bc, blr, li, midasm, switch_with};
use crate::{Action, Hooks, MidAsm};

fn site(kind: SiteKind, target: u32) -> Site {
    Site { kind, target }
}

/// The sites of each block of the function that fills `bytes`, by block start, with `midasm`
/// hooks.
fn sites_of(bytes: &[u8], midasm: Vec<MidAsm>) -> Vec<(u32, Vec<Site>)> {
    let function = Function {
        addr: BASE,
        size: bytes.len() as u32,
    };
    let routines = SaveRestore::new();
    let hooks = Hooks {
        overrides: Vec::new(),
        midasm,
    };
    let program = Program::new(Code::new(BASE, bytes), [function], &routines).with_hooks(hooks);
    program.check_hooks().unwrap();
    let cfg = program.blocks(function).unwrap();
    cfg.blocks
        .iter()
        .map(|block| (block.start, transfers(&program, function, &cfg, block)))
        .collect()
}

#[test]
fn a_conditional_branch_inside_is_taken_then_goes_on() {
    // beq +8; li r3,1; blr
    let bytes = assemble(&[bc(12, 2, 8), li(3, 1), blr()]);
    assert_eq!(
        sites_of(&bytes, Vec::new()),
        [
            (
                BASE,
                vec![
                    site(SiteKind::Branch, BASE + 8),
                    site(SiteKind::Next, BASE + 4)
                ]
            ),
            (BASE + 4, vec![site(SiteKind::Next, BASE + 8)]),
            (BASE + 8, vec![]),
        ]
    );
}

#[test]
fn a_branch_to_the_next_instruction_has_two_sites() {
    // beq +4; blr: both sides reach the same block, from two places in the code.
    let bytes = assemble(&[bc(12, 2, 4), blr()]);
    assert_eq!(
        sites_of(&bytes, Vec::new()),
        [
            (
                BASE,
                vec![
                    site(SiteKind::Branch, BASE + 4),
                    site(SiteKind::Next, BASE + 4)
                ]
            ),
            (BASE + 4, vec![]),
        ]
    );
}

#[test]
fn leaving_the_function_is_no_site() {
    // beqlr; li r3,1; b out of the function.
    let beqlr = Insn::Bclr {
        bo: 12,
        bi: CrBit(2),
        bh: 0,
        lk: false,
    };
    let bytes = assemble(&[beqlr, li(3, 1), b(0x100, false)]);
    assert_eq!(
        sites_of(&bytes, Vec::new()),
        [
            (BASE, vec![site(SiteKind::Next, BASE + 4)]),
            (BASE + 4, vec![]),
        ]
    );
}

#[test]
fn a_jump_table_has_one_site_per_distinct_target_in_address_order() {
    let table = |entries| {
        let sites = sites_of(&switch_with(entries), Vec::new());
        assert_eq!(sites[1].0, BASE + 8, "{sites:?}");
        sites[1].1.clone()
    };
    assert_eq!(
        table([BASE + 0x2C, BASE + 0x28]),
        [
            site(SiteKind::Table, BASE + 0x28),
            site(SiteKind::Table, BASE + 0x2C)
        ]
    );
    assert_eq!(
        table([BASE + 0x2C, BASE + 0x2C]),
        [site(SiteKind::Table, BASE + 0x2C)]
    );
}

#[test]
fn hook_jumps_come_before_or_after_their_instruction() {
    // li r3,1; li r4,2; blr; li r3,9; blr, with a jump before and a jump after word 0.
    let bytes = assemble(&[li(3, 1), li(4, 2), blr(), li(3, 9), blr()]);
    let midasm = vec![
        midasm(0, "after", true, Action::Jump(BASE + 4)),
        midasm(0, "before", false, Action::JumpIfTrue(BASE + 12)),
        midasm(0, "plain", false, Action::Continue),
    ];
    assert_eq!(
        sites_of(&bytes, midasm),
        [
            (
                BASE,
                vec![
                    site(SiteKind::Hook, BASE + 12),
                    site(SiteKind::Hook, BASE + 4),
                    site(SiteKind::Next, BASE + 4),
                ]
            ),
            (BASE + 4, vec![]),
            (BASE + 12, vec![]),
        ]
    );
}
