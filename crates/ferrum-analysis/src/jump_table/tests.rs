// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::*;
use crate::asm::*;

const BASE: u32 = 0x8200_0000;

/// The code, with `data` after it, and the address of the `bctr`, the last instruction.
fn image(insns: &[Insn], data: &[u8]) -> (Vec<u8>, u32) {
    let mut bytes = assemble(insns);
    let bctr = BASE + bytes.len() as u32 - 4;
    bytes.extend_from_slice(data);
    (bytes, bctr)
}

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|w| w.to_be_bytes()).collect()
}

fn detect_in(bytes: &[u8], bctr: u32, entries: Option<u32>) -> Detection {
    detect(
        &Code::new(BASE, bytes),
        BASE,
        bctr,
        &BTreeSet::new(),
        entries,
    )
}

/// The prologue of the address form the target game uses: bound check, table address, scaled
/// index, load into CTR.
fn addresses(index: u8, bound: u16, table: u32) -> Vec<Insn> {
    let mut insns = vec![cmplwi(6, index, bound), bgt(6, 0x100)];
    insns.extend(load_address(12, table));
    insns.extend([slwi(0, index, 2), lwzx(0, 12, 0), mtctr(0), bctr()]);
    insns
}

#[test]
fn a_table_of_addresses_after_the_bctr() {
    let table = BASE + 8 * 4;
    let targets = [BASE + 0x40, BASE + 0x48, BASE + 0x40];
    let (bytes, bctr) = image(&addresses(10, 2, table), &words(&targets));
    assert_eq!(bctr, BASE + 0x1C);
    assert_eq!(
        detect_in(&bytes, bctr, None),
        Detection::Table(JumpTable {
            table,
            entry_size: 4,
            targets: targets.to_vec(),
        })
    );
}

#[test]
fn a_table_of_byte_offsets_scaled_by_four() {
    // lbzx from the byte table, shifted by 2 and added to the address after the bctr.
    let mut insns = vec![cmplwi(6, 11, 3), bgt(6, 0x100)];
    let bytes_at = BASE + 0x100;
    insns.extend(load_address(12, bytes_at));
    insns.extend([lbzx(0, 12, 11), slwi(0, 0, 2)]);
    let after = BASE + 4 * 12;
    insns.extend(load_address(12, after));
    insns.extend([add(12, 12, 0), mtctr(12), nop(), bctr()]);
    let mut data = vec![0; 0x100 - insns.len() * 4];
    data.extend_from_slice(&[0, 3, 1, 3]);
    let (bytes, bctr) = image(&insns, &data);
    assert_eq!(bctr + 4, after);
    assert_eq!(
        detect_in(&bytes, bctr, None),
        Detection::Table(JumpTable {
            table: bytes_at,
            entry_size: 1,
            targets: vec![after, after + 12, after + 4, after + 12],
        })
    );
}

#[test]
fn a_table_of_halfword_offsets_in_bytes() {
    // lhzx at index * 2, added to the base without a shift.
    let mut insns = vec![cmplwi(6, 11, 1), bgt(6, 0x100)];
    let halves_at = BASE + 0x100;
    insns.extend(load_address(12, halves_at));
    insns.extend([slwi(0, 11, 1), lhzx(0, 12, 0)]);
    let after = BASE + 4 * 12;
    insns.extend(load_address(12, after));
    insns.extend([add(12, 12, 0), mtctr(12), nop(), bctr()]);
    let mut data = vec![0; 0x100 - insns.len() * 4];
    data.extend_from_slice(&[0x01, 0x04, 0x00, 0x08]);
    let (bytes, bctr) = image(&insns, &data);
    assert_eq!(
        detect_in(&bytes, bctr, None),
        Detection::Table(JumpTable {
            table: halves_at,
            entry_size: 2,
            targets: vec![after + 0x104, after + 8],
        })
    );
}

#[test]
fn bound_checks_by_return_and_by_not_less() {
    // bgtlr cr6 after cmplwi gives K + 1 entries; bge cr7 (branch if LT is clear) gives K.
    let table = BASE + 8 * 4;
    let mut insns = addresses(10, 1, table);
    insns[1] = bclr(12, 4 * 6 + 1);
    let (bytes, bctr) = image(&insns, &words(&[BASE, BASE]));
    let Detection::Table(found) = detect_in(&bytes, bctr, None) else {
        panic!("no table");
    };
    assert_eq!(found.targets.len(), 2);

    let mut insns = addresses(10, 2, table);
    insns[0] = cmplwi(7, 10, 2);
    insns[1] = bc(4, 4 * 7, 0x100);
    let (bytes, bctr) = image(&insns, &words(&[BASE, BASE]));
    let Detection::Table(found) = detect_in(&bytes, bctr, None) else {
        panic!("no table");
    };
    assert_eq!(found.targets.len(), 2);
}

#[test]
fn a_bound_check_on_another_field_bounds_nothing() {
    // The shape of seq_jumptable_constants: cmpwi cr6, then bgt on cr0. Only the count of
    // `[analysis] jump_tables` resolves it.
    let table = BASE + 8 * 4;
    let mut insns = addresses(3, 3, table);
    insns[0] = cmpwi(6, 3, 3);
    insns[1] = bgt(0, 0x100);
    let targets = [BASE + 0x30, BASE + 0x38, BASE + 0x40, BASE + 0x48];
    let (bytes, bctr) = image(&insns, &words(&targets));
    assert_eq!(detect_in(&bytes, bctr, None), Detection::Unresolved);
    assert_eq!(
        detect_in(&bytes, bctr, Some(4)),
        Detection::Table(JumpTable {
            table,
            entry_size: 4,
            targets: targets.to_vec(),
        })
    );
}

#[test]
fn a_changed_index_or_a_call_loses_the_bound() {
    let table = BASE + 9 * 4;
    // The index is rewritten after the bound check.
    let mut insns = addresses(10, 2, table);
    insns.insert(2, addi(10, 10, 1));
    let (bytes, bctr) = image(&insns, &words(&[BASE; 3]));
    assert_eq!(detect_in(&bytes, bctr, None), Detection::Unresolved);
    // A call between the load of the table address and its use: nothing is known after it.
    let mut insns = addresses(10, 2, table);
    insns.insert(4, b(0x200, true));
    let (bytes, bctr) = image(&insns, &words(&[BASE; 3]));
    assert_eq!(detect_in(&bytes, bctr, None), Detection::Indirect);
}

#[test]
fn a_virtual_call_is_no_table() {
    // lwz r11,0(r3); lwz r11,16(r11); mtctr r11; bctr
    let insns = [lwz(11, 0, 3), lwz(11, 16, 11), mtctr(11), bctr()];
    let (bytes, at) = image(&insns, &[]);
    assert_eq!(detect_in(&bytes, at, None), Detection::Indirect);
    // Nor is a bctr with nothing before it.
    let (bytes, at) = image(&[bctr()], &[]);
    assert_eq!(detect_in(&bytes, at, None), Detection::Indirect);
}

#[test]
fn the_run_stops_at_an_unconditional_branch_and_at_the_floor() {
    // Everything before the blr belongs to another path, so the bound check is not seen.
    let table = BASE + 9 * 4;
    let mut insns = addresses(10, 2, table);
    insns.insert(2, blr());
    let (bytes, bctr) = image(&insns, &words(&[BASE; 3]));
    assert_eq!(detect_in(&bytes, bctr, None), Detection::Unresolved);
    // A floor after the bound check hides it too.
    let (bytes, bctr) = image(&addresses(10, 2, BASE + 8 * 4), &words(&[BASE; 3]));
    let code = Code::new(BASE, &bytes);
    let joins = BTreeSet::new();
    assert_eq!(
        detect(&code, BASE + 8, bctr, &joins, None),
        Detection::Unresolved
    );
}

#[test]
fn a_path_that_joins_after_the_bound_check_loses_it() {
    // A branch to the instruction after the bgt brings another path in, which did not pass the
    // bound check.
    let table = BASE + 8 * 4;
    let (bytes, bctr) = image(&addresses(10, 2, table), &words(&[BASE; 3]));
    let code = Code::new(BASE, &bytes);
    let joins = BTreeSet::from([BASE + 8]);
    assert_eq!(
        detect(&code, BASE, bctr, &joins, None),
        Detection::Unresolved
    );
    // A join at the bound check changes nothing.
    let mut insns = vec![li(3, 0)];
    insns.extend(addresses(10, 2, BASE + 9 * 4));
    let (bytes, bctr) = image(&insns, &words(&[BASE; 3]));
    let code = Code::new(BASE, &bytes);
    let joins = BTreeSet::from([BASE + 4]);
    assert!(matches!(
        detect(&code, BASE, bctr, &joins, None),
        Detection::Table(_)
    ));
}

#[test]
fn a_constant_from_another_path_is_forgotten_at_the_join() {
    // li r10,0 falls into a loop head that a later branch targets: at the join r10 is no longer
    // the constant, so the table it indexes is still found.
    let table = BASE + 9 * 4;
    let mut insns = vec![li(10, 0)];
    insns.extend(addresses(10, 2, table));
    let (bytes, bctr) = image(&insns, &words(&[BASE; 3]));
    let code = Code::new(BASE, &bytes);
    assert_eq!(
        detect(&code, BASE, bctr, &BTreeSet::new(), None),
        Detection::Indirect,
        "without the join, r10 looks constant"
    );
    let joins = BTreeSet::from([BASE + 4]);
    assert!(matches!(
        detect(&code, BASE, bctr, &joins, None),
        Detection::Table(_)
    ));
}

#[test]
fn a_table_past_the_code_is_unresolved() {
    let (bytes, bctr) = image(&addresses(10, 2, BASE + 8 * 4), &words(&[BASE; 2]));
    assert_eq!(detect_in(&bytes, bctr, None), Detection::Unresolved);
}
