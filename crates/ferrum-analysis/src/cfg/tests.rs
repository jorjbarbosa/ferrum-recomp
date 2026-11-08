// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::*;
use crate::asm::*;

const BASE: u32 = 0x8200_0000;

fn cfg_of(bytes: &[u8], size: u32) -> Result<Cfg, Error> {
    build(
        &Code::new(BASE, bytes),
        Function { addr: BASE, size },
        &Rules::default(),
    )
}

/// The start, the instruction count and the exit of every block.
fn shape(cfg: &Cfg) -> Vec<(u32, usize, Exit)> {
    cfg.blocks
        .iter()
        .map(|block| (block.start - BASE, block.insns.len(), block.exit))
        .collect()
}

#[test]
fn straight_code_is_one_block() {
    let bytes = assemble(&[li(3, 1), li(4, 2), blr()]);
    let cfg = cfg_of(&bytes, 12).unwrap();
    assert_eq!(shape(&cfg), [(0, 3, Exit::Jump)]);
    assert_eq!(cfg.blocks[0].insns[1], (BASE + 4, li(4, 2)));
    assert!(!cfg.falls_off());
}

#[test]
fn a_conditional_branch_splits_at_its_target_and_after_it() {
    // The shape of test_nor_cr_1: bne over one instruction into a label that returns.
    let bytes = assemble(&[li(3, 0), bc(4, 2, 8), li(3, 1), blr()]);
    let cfg = cfg_of(&bytes, 16).unwrap();
    assert_eq!(
        shape(&cfg),
        [
            (0, 2, Exit::Next(BASE + 8)),
            (8, 1, Exit::Next(BASE + 12)),
            (12, 1, Exit::Jump),
        ]
    );
}

#[test]
fn a_loop_back_splits_at_its_head() {
    // li; mtctr-free loop: head: addi; bdnz head; blr.
    let bytes = assemble(&[li(3, 0), li(4, 1), bc(16, 0, -4), blr()]);
    let cfg = cfg_of(&bytes, 16).unwrap();
    assert_eq!(
        shape(&cfg),
        [
            (0, 1, Exit::Next(BASE + 4)),
            (4, 2, Exit::Next(BASE + 12)),
            (12, 1, Exit::Jump),
        ]
    );
}

#[test]
fn calls_do_not_end_a_block() {
    let bytes = assemble(&[li(3, 0), b(0x100, true), li(4, 1), blr()]);
    let cfg = cfg_of(&bytes, 16).unwrap();
    assert_eq!(shape(&cfg), [(0, 4, Exit::Jump)]);
}

#[test]
fn branches_out_of_the_function_end_the_block_without_a_new_one() {
    // b to the next function, and beq to it with a fall-through.
    let bytes = assemble(&[bc(12, 2, 0x40), li(3, 1), b(0x40, false), li(4, 4)]);
    let cfg = cfg_of(&bytes, 16).unwrap();
    assert_eq!(
        shape(&cfg),
        [(0, 1, Exit::Next(BASE + 4)), (4, 2, Exit::Jump)]
    );
}

#[test]
fn a_branch_to_the_entry_stays_inside() {
    let bytes = assemble(&[li(3, 1), bc(12, 2, -4), blr()]);
    let cfg = cfg_of(&bytes, 12).unwrap();
    assert_eq!(
        shape(&cfg),
        [(0, 2, Exit::Next(BASE + 8)), (8, 1, Exit::Jump)]
    );
}

#[test]
fn words_no_path_reaches_are_not_decoded() {
    let mut bytes = assemble(&[li(3, 1), blr()]);
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    let cfg = cfg_of(&bytes, 12).unwrap();
    assert_eq!(shape(&cfg), [(0, 2, Exit::Jump)]);
}

#[test]
fn an_undecodable_word_on_a_path_is_an_error() {
    let mut bytes = assemble(&[li(3, 1)]);
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend(assemble(&[blr()]));
    assert_eq!(
        cfg_of(&bytes, 12),
        Err(Error::Undecodable {
            function: BASE,
            addr: BASE + 4,
            word: 0
        })
    );
}

#[test]
fn running_past_the_end_falls_off() {
    let bytes = assemble(&[li(3, 1), li(4, 2), blr()]);
    let cfg = cfg_of(&bytes, 8).unwrap();
    assert_eq!(shape(&cfg), [(0, 2, Exit::FallOff)]);
    assert!(cfg.falls_off());
    // A conditional branch at the end falls off when it is not taken.
    let bytes = assemble(&[li(3, 1), bc(12, 2, -4)]);
    let cfg = cfg_of(&bytes, 8).unwrap();
    assert_eq!(shape(&cfg), [(0, 2, Exit::FallOff)]);
}

#[test]
fn a_range_past_the_code_or_without_an_instruction_is_an_error() {
    let bytes = assemble(&[li(3, 1)]);
    assert_eq!(
        cfg_of(&bytes, 8),
        Err(Error::OutsideCode {
            function: BASE,
            addr: BASE + 4
        })
    );
    for (addr, size) in [(BASE, 0), (BASE, 3), (BASE + 2, 8)] {
        let code = Code::new(BASE, &bytes);
        assert_eq!(
            build(&code, Function { addr, size }, &Rules::default()),
            Err(Error::BadFunction {
                function: addr,
                size
            })
        );
    }
}

#[test]
fn a_jump_table_starts_a_block_at_each_target_and_ends_its_own() {
    // cmplwi cr6,r10,1; bgt cr6 to case 1; lis/addi r12,table; slwi r0,r10,2;
    // lwzx r0,r12,r0; mtctr r0; bctr; two table words; case 1: li r3,1; case 0: blr.
    let table = BASE + 0x20;
    let mut insns = vec![cmplwi(6, 10, 1), bgt(6, 0x24)];
    insns.extend(load_address(12, table));
    insns.extend([slwi(0, 10, 2), lwzx(0, 12, 0), mtctr(0), bctr()]);
    let mut bytes = assemble(&insns);
    bytes.extend((BASE + 0x2C).to_be_bytes());
    bytes.extend((BASE + 0x28).to_be_bytes());
    bytes.extend(assemble(&[li(3, 1), blr()]));
    let cfg = cfg_of(&bytes, bytes.len() as u32).unwrap();
    assert_eq!(
        shape(&cfg),
        [
            (0, 2, Exit::Next(BASE + 8)),
            (8, 6, Exit::Jump),
            (0x28, 1, Exit::Next(BASE + 0x2C)),
            (0x2C, 1, Exit::Jump),
        ]
    );
    assert_eq!(
        cfg.tables[&(BASE + 0x1C)].targets,
        [BASE + 0x2C, BASE + 0x28]
    );
    assert!(cfg.unresolved.is_empty());
    assert_eq!(cfg.reach(), u64::from(BASE) + 0x30);
}

#[test]
fn a_table_with_a_target_outside_the_function_is_unresolved() {
    let table = BASE + 0x20;
    let mut insns = vec![cmplwi(6, 10, 0), bgt(6, 0x24)];
    insns.extend(load_address(12, table));
    insns.extend([slwi(0, 10, 2), lwzx(0, 12, 0), mtctr(0), bctr()]);
    let mut bytes = assemble(&insns);
    bytes.extend((BASE + 0x100).to_be_bytes());
    bytes.extend(assemble(&[blr()]));
    let cfg = cfg_of(&bytes, bytes.len() as u32).unwrap();
    assert!(cfg.tables.is_empty());
    assert_eq!(cfg.unresolved, BTreeSet::from([BASE + 0x1C]));
    // Without the bound check, the count from the config resolves it once the target is inside.
    let mut bytes = assemble(&insns);
    bytes.extend((BASE + 0x24).to_be_bytes());
    bytes.extend(assemble(&[blr()]));
    let rules = Rules {
        table_entries: BTreeMap::from([(BASE + 0x1C, 1)]),
        ..Rules::default()
    };
    let code = Code::new(BASE, &bytes);
    let function = Function {
        addr: BASE,
        size: bytes.len() as u32,
    };
    let cfg = build(&code, function, &rules).unwrap();
    assert_eq!(cfg.tables[&(BASE + 0x1C)].targets, [BASE + 0x24]);
}

#[test]
fn a_call_that_never_returns_ends_its_path() {
    // li r3,1; bl +0x100; then words no path should reach.
    let mut bytes = assemble(&[li(3, 1), b(0x100, true)]);
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    let code = Code::new(BASE, &bytes);
    let function = Function {
        addr: BASE,
        size: 12,
    };
    assert!(matches!(
        build(&code, function, &Rules::default()),
        Err(Error::Undecodable { .. })
    ));
    let rules = Rules {
        no_return: BTreeSet::from([BASE + 0x104]),
        ..Rules::default()
    };
    let cfg = build(&code, function, &rules).unwrap();
    assert_eq!(shape(&cfg), [(0, 2, Exit::NoReturn)]);
    assert_eq!(cfg.reach(), u64::from(BASE) + 8);
    // A conditional call to it, or a call to another function, goes on.
    let insn = bc(12, 2, 0x100);
    let Insn::Bc { bo, bi, bd, aa, .. } = insn else {
        unreachable!()
    };
    let call = Insn::Bc {
        bo,
        bi,
        bd,
        aa,
        lk: true,
    };
    assert!(!rules.never_returns(&call, BASE + 4));
    assert!(!rules.never_returns(&b(0x200, true), BASE + 4));
    assert!(!rules.never_returns(&b(0x100, false), BASE + 4));
}

#[test]
fn a_case_that_branches_back_past_the_bound_check_leaves_the_table_unresolved() {
    // The table resolves on the first walk; its first case then branches back to the lis after
    // the bgt, a path the bound check does not cover, and the next walk gives the table up.
    let table = BASE + 0x20;
    let mut insns = vec![cmplwi(6, 10, 1), bgt(6, 0x2C)];
    insns.extend(load_address(12, table));
    insns.extend([slwi(0, 10, 2), lwzx(0, 12, 0), mtctr(0), bctr()]);
    let mut bytes = assemble(&insns);
    bytes.extend((BASE + 0x28).to_be_bytes());
    bytes.extend((BASE + 0x2C).to_be_bytes());
    bytes.extend(assemble(&[b(-0x20, false), blr(), blr()]));
    let cfg = cfg_of(&bytes, bytes.len() as u32).unwrap();
    assert!(cfg.tables.is_empty());
    assert_eq!(cfg.unresolved, BTreeSet::from([BASE + 0x1C]));
    // Without that branch the table stays.
    let mut bytes = assemble(&insns);
    bytes.extend((BASE + 0x28).to_be_bytes());
    bytes.extend((BASE + 0x2C).to_be_bytes());
    bytes.extend(assemble(&[blr(), blr(), blr()]));
    let cfg = cfg_of(&bytes, bytes.len() as u32).unwrap();
    assert_eq!(cfg.tables.len(), 1);
}

#[test]
fn the_instruction_after_a_call_that_returns_twice_starts_a_block() {
    // li r3,0x100; bl setjmp; cmpwi r3,0; blr
    let bytes = assemble(&[li(3, 0x100), b(0x100, true), cmpwi(0, 3, 0), blr()]);
    let code = Code::new(BASE, &bytes);
    let function = Function {
        addr: BASE,
        size: 16,
    };
    let cfg = build(&code, function, &Rules::default()).unwrap();
    assert_eq!(shape(&cfg), [(0, 4, Exit::Jump)]);
    let rules = Rules {
        returns_twice: BTreeSet::from([BASE + 0x104]),
        ..Rules::default()
    };
    let cfg = build(&code, function, &rules).unwrap();
    assert_eq!(
        shape(&cfg),
        [(0, 2, Exit::Next(BASE + 8)), (8, 2, Exit::Jump)]
    );
}

#[test]
fn a_join_from_outside_the_code_starts_a_block_that_no_path_reaches() {
    // li r3,1; blr; li r3,2; blr: the second half only a hook's jump reaches.
    let bytes = assemble(&[li(3, 1), blr(), li(3, 2), blr()]);
    let code = Code::new(BASE, &bytes);
    let function = Function {
        addr: BASE,
        size: 16,
    };
    let rules = Rules {
        joins: BTreeSet::from([BASE + 8, BASE + 0x100]),
        ..Rules::default()
    };
    let cfg = build(&code, function, &rules).unwrap();
    assert_eq!(shape(&cfg), [(0, 2, Exit::Jump), (8, 2, Exit::Jump)]);
}
