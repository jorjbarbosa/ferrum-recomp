// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use ferrum_decoder::{Gpr, Insn};

use super::*;
use crate::asm::{
    addi, b, bc, bclr, bctr, blr, cmplwi, cmpwi, lbzx, li, load_address, lwzx, mtctr, nop, slwi,
};
use crate::cfg::{Rules, build};
use crate::code::Code;

const BASE: u32 = 0x8200_0000;

/// An instruction or a raw word of data, such as a table entry.
enum Part {
    I(Insn),
    W(u32),
}

/// The byte displacement from the word at index `from` to the word at index `to`.
fn disp(from: usize, to: usize) -> i16 {
    ((to as i32 - from as i32) * 4) as i16
}

fn bgt(cr: u8, bd: i16) -> Insn {
    bc(12, 4 * cr + 1, bd)
}

fn ble(cr: u8, bd: i16) -> Insn {
    bc(4, 4 * cr + 1, bd)
}

fn blt(cr: u8, bd: i16) -> Insn {
    bc(12, 4 * cr, bd)
}

fn beq(cr: u8, bd: i16) -> Insn {
    bc(12, 4 * cr + 2, bd)
}

fn bne(cr: u8, bd: i16) -> Insn {
    bc(4, 4 * cr + 2, bd)
}

fn rlwinm(ra: u8, rs: u8, sh: u8, mb: u8, me: u8) -> Insn {
    Insn::Rlwinm {
        ra: Gpr(ra),
        rs: Gpr(rs),
        sh,
        mb,
        me,
        rc: false,
    }
}

fn andi_dot(ra: u8, rs: u8, ui: u16) -> Insn {
    Insn::AndiDot {
        ra: Gpr(ra),
        rs: Gpr(rs),
        ui,
    }
}

fn lbz(rt: u8, d: i16, ra: u8) -> Insn {
    Insn::Lbz {
        rt: Gpr(rt),
        d,
        ra: Gpr(ra),
    }
}

fn lhzx(rt: u8, ra: u8, rb: u8) -> Insn {
    Insn::Lhzx {
        rt: Gpr(rt),
        ra: Gpr(ra),
        rb: Gpr(rb),
    }
}

/// The intervals at `points`, (word index, GPR), of the function the parts make, with the words
/// at the indexes in `externals` reached from outside.
fn query(parts: &[Part], externals: &[usize], points: &[(usize, u8)]) -> Vec<Range> {
    let bytes: Vec<u8> = parts
        .iter()
        .flat_map(|part| {
            match part {
                Part::I(insn) => insn.encode(),
                Part::W(word) => *word,
            }
            .to_be_bytes()
        })
        .collect();
    let code = Code::new(BASE, &bytes);
    let function = Function {
        addr: BASE,
        size: bytes.len() as u32,
    };
    let externals: BTreeSet<u32> = externals.iter().map(|&i| BASE + 4 * i as u32).collect();
    let rules = Rules {
        joins: externals.clone(),
        ..Rules::default()
    };
    let cfg = build(&code, function, &rules).expect("the test code builds");
    let tables: BTreeMap<u32, Vec<u32>> = cfg
        .tables
        .iter()
        .map(|(&bctr, table)| (bctr, table.targets.clone()))
        .collect();
    let ranges = analyze(function, &cfg.blocks, &tables, &externals);
    points
        .iter()
        .map(|&(index, reg)| ranges.before(BASE + 4 * index as u32, reg))
        .collect()
}

fn insns(insns: &[Insn]) -> Vec<Part> {
    insns.iter().map(|&insn| Part::I(insn)).collect()
}

const ANY: Range = Range::Unknown;

#[test]
fn a_compare_narrows_both_edges_of_its_branch() {
    let code = insns(&[
        cmplwi(6, 3, 5),
        bgt(6, disp(1, 4)),
        nop(),
        blr(),
        nop(),
        blr(),
    ]);
    assert_eq!(
        query(&code, &[], &[(2, 3), (4, 3)]),
        [Range::Span(0, 5), Range::Span(6, u32::MAX)]
    );
    // ble takes the bounded edge to its target.
    let code = insns(&[
        cmplwi(6, 3, 5),
        ble(6, disp(1, 4)),
        nop(),
        blr(),
        nop(),
        blr(),
    ]);
    assert_eq!(
        query(&code, &[], &[(2, 3), (4, 3)]),
        [Range::Span(6, u32::MAX), Range::Span(0, 5)]
    );
}

#[test]
fn paths_join_into_the_union_and_an_unchecked_path_into_unknown() {
    let program = |second: [Insn; 2]| {
        insns(&[
            cmplwi(6, 4, 0),
            beq(6, disp(1, 6)),
            cmplwi(6, 3, 3),
            bgt(6, disp(3, 12)),
            b(i32::from(disp(4, 10)), false),
            nop(),
            second[0],
            second[1],
            b(i32::from(disp(8, 10)), false),
            nop(),
            nop(),
            blr(),
            blr(),
        ])
    };
    let checked = program([cmplwi(6, 3, 7), bgt(6, disp(7, 12))]);
    assert_eq!(query(&checked, &[], &[(10, 3)]), [Range::Span(0, 7)]);
    let unchecked = program([nop(), nop()]);
    assert_eq!(query(&unchecked, &[], &[(10, 3)]), [ANY]);
}

#[test]
fn constants_of_each_path_join_into_an_interval() {
    let code = insns(&[
        cmplwi(6, 4, 0),
        beq(6, disp(1, 4)),
        li(18, 3),
        b(i32::from(disp(3, 5)), false),
        li(18, 6),
        nop(),
        blr(),
    ]);
    assert_eq!(query(&code, &[], &[(5, 18)]), [Range::Span(3, 6)]);
}

#[test]
fn masks_and_narrow_loads_bound_their_result() {
    let code = insns(&[
        // extrwi r4,r5,4,8: four bits, 0 to 15.
        rlwinm(4, 5, 20, 28, 31),
        andi_dot(6, 5, 0x1F),
        lbz(7, 0, 5),
        lhzx(8, 5, 6),
        // srwi r9,r7,4: a byte shifted right by 4.
        rlwinm(9, 7, 28, 4, 31),
        // slwi r10,r7,2: a byte times 4.
        slwi(10, 7, 2),
        blr(),
    ]);
    assert_eq!(
        query(
            &code,
            &[],
            &[(6, 4), (6, 6), (6, 7), (6, 8), (6, 9), (6, 10)]
        ),
        [
            Range::Span(0, 15),
            Range::Span(0, 0x1F),
            Range::Span(0, 0xFF),
            Range::Span(0, 0xFFFF),
            Range::Span(0, 0xF),
            Range::Span(0, 0x3FC),
        ]
    );
}

#[test]
fn an_offset_shifts_an_interval_unless_it_wraps() {
    let code = insns(&[
        cmplwi(6, 3, 10),
        bgt(6, disp(1, 9)),
        // r3 may be 0 here, so r3 - 1 may wrap.
        addi(4, 3, -1),
        cmplwi(6, 3, 1),
        blt(6, disp(4, 9)),
        addi(5, 3, -1),
        addi(6, 3, 4096),
        nop(),
        blr(),
        blr(),
    ]);
    assert_eq!(
        query(&code, &[], &[(3, 4), (7, 5), (7, 6)]),
        [ANY, Range::Span(0, 9), Range::Span(4097, 4106)]
    );
}

#[test]
fn a_loop_counter_is_bounded_by_its_exit_or_widens() {
    // The loop runs while r9 != 5: inside, r9 goes from 1 to 5, and it is 5 after the loop.
    let counted = insns(&[
        li(9, 0),
        addi(9, 9, 1),
        cmpwi(6, 9, 5),
        bne(6, disp(3, 1)),
        nop(),
        blr(),
    ]);
    assert_eq!(
        query(&counted, &[], &[(2, 9), (4, 9)]),
        [Range::Span(1, 5), Range::Span(5, 5)]
    );
    // The loop runs on r10: r9 grows at every pass until it widens to unknown.
    let unbounded = insns(&[
        li(9, 0),
        addi(9, 9, 1),
        cmpwi(6, 10, 0),
        bne(6, disp(3, 1)),
        nop(),
        blr(),
    ]);
    assert_eq!(query(&unbounded, &[], &[(2, 9), (4, 9)]), [ANY, ANY]);
}

#[test]
fn a_call_keeps_the_registers_the_abi_preserves() {
    let code = insns(&[li(3, 5), li(24, 9), b(0x1000, true), nop(), blr()]);
    assert_eq!(
        query(&code, &[], &[(2, 3), (3, 3), (3, 24)]),
        [Range::Span(5, 5), ANY, Range::Span(9, 9)]
    );
}

#[test]
fn only_an_unchanged_compare_narrows_a_branch() {
    // A load between the compare and the branch keeps it.
    let kept = insns(&[
        cmplwi(6, 3, 5),
        lbzx(4, 5, 6),
        bgt(6, disp(2, 5)),
        nop(),
        blr(),
        blr(),
    ]);
    assert_eq!(query(&kept, &[], &[(3, 3)]), [Range::Span(0, 5)]);
    // andi. writes CR0, so the branch on it says nothing of r3.
    let recorded = insns(&[
        cmplwi(0, 3, 5),
        andi_dot(4, 4, 1),
        bgt(0, disp(2, 5)),
        nop(),
        blr(),
        blr(),
    ]);
    assert_eq!(query(&recorded, &[], &[(3, 3)]), [ANY]);
    // r3 changes after the compare: narrowing it would make the fallthrough look unreachable.
    let changed = insns(&[
        cmplwi(6, 3, 5),
        li(3, 100),
        bgt(6, disp(2, 5)),
        nop(),
        blr(),
        blr(),
    ]);
    assert_eq!(query(&changed, &[], &[(3, 3)]), [Range::Span(100, 100)]);
}

#[test]
fn a_conditional_return_narrows_its_fallthrough() {
    // bgelr cr6
    let code = insns(&[cmplwi(6, 11, 1), bclr(4, 24), nop(), blr()]);
    assert_eq!(query(&code, &[], &[(2, 11)]), [Range::Span(0, 0)]);
}

#[test]
fn the_targets_of_a_table_keep_the_bound_of_its_index() {
    // A table of three addresses right after the bctr, then the three cases and the default.
    let table = BASE + 4 * 8;
    let case = |index: u32| BASE + 4 * (11 + 2 * index);
    let mut code = insns(&[
        cmplwi(6, 9, 2),
        bgt(6, disp(1, 17)),
        load_address(11, table)[0],
        load_address(11, table)[1],
        slwi(10, 9, 2),
        lwzx(12, 11, 10),
        mtctr(12),
        bctr(),
    ]);
    code.extend([Part::W(case(0)), Part::W(case(1)), Part::W(case(2))]);
    code.extend(insns(&[nop(), blr(), nop(), blr(), nop(), blr(), blr()]));
    assert_eq!(
        query(&code, &[], &[(11, 9), (13, 9), (15, 9)]),
        [Range::Span(0, 2); 3]
    );
}

#[test]
fn an_external_join_starts_unknown() {
    let code = insns(&[
        cmplwi(6, 3, 5),
        bgt(6, disp(1, 4)),
        nop(),
        blr(),
        nop(),
        blr(),
    ]);
    assert_eq!(query(&code, &[2], &[(2, 3)]), [ANY]);
}

#[test]
fn narrowing_follows_each_relation() {
    let span = Range::Span(2, 9);
    let cases = [
        (Relation::Lt, 5, Some(Range::Span(2, 4))),
        (Relation::Le, 5, Some(Range::Span(2, 5))),
        (Relation::Gt, 5, Some(Range::Span(6, 9))),
        (Relation::Ge, 5, Some(Range::Span(5, 9))),
        (Relation::Eq, 5, Some(Range::Span(5, 5))),
        (Relation::Ne, 5, Some(Range::Span(2, 9))),
        (Relation::Ne, 2, Some(Range::Span(3, 9))),
        (Relation::Ne, 9, Some(Range::Span(2, 8))),
        (Relation::Lt, 2, None),
        (Relation::Gt, 9, None),
        (Relation::Eq, 10, None),
    ];
    for (relation, imm, expected) in cases {
        assert_eq!(narrow(span, relation, imm), expected, "{relation:?} {imm}");
    }
    assert_eq!(narrow(ANY, Relation::Lt, 0), None);
    assert_eq!(narrow(Range::Span(7, 7), Relation::Ne, 7), None);
    assert_eq!(narrow(ANY, Relation::Le, 3), Some(Range::Span(0, 3)));
}
