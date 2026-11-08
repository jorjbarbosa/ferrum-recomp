// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::*;
use crate::asm::*;
use crate::save_restore::{Family, Routine};

const BASE: u32 = 0x8200_0000;

/// A word of a test image: an instruction, or data.
enum W {
    I(Insn),
    D(u32),
}

use W::{D, I};

fn bytes_of(words: &[W]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| match word {
            I(insn) => insn.encode().to_be_bytes(),
            D(value) => value.to_be_bytes(),
        })
        .collect()
}

/// An input whose first `code_words` words are code and the rest data.
fn input<'a>(bytes: &'a [u8], code_words: u32, routines: &'a SaveRestore) -> Input<'a> {
    let code_end = BASE + 4 * code_words;
    Input {
        code: Code::new(BASE, bytes),
        code_ranges: std::iter::once(BASE..code_end).collect(),
        data_ranges: std::iter::once(code_end..BASE + bytes.len() as u32).collect(),
        pdata: Vec::new(),
        entries: Vec::new(),
        thunks: BTreeSet::new(),
        routines,
        functions: Vec::new(),
        skip: Vec::new(),
        table_entries: BTreeMap::new(),
        longjmp: None,
    }
}

fn at(offset: u32, size: u32) -> Function {
    Function {
        addr: BASE + offset,
        size,
    }
}

/// Each function as its offset, its size and its source.
fn found(discovery: &Discovery) -> Vec<(u32, u32, Source)> {
    discovery
        .functions
        .iter()
        .map(|f| (f.addr - BASE, f.size, discovery.sources[&f.addr]))
        .collect()
}

#[test]
fn a_call_target_in_a_gap_is_a_function_and_the_sweep_takes_the_rest() {
    let words = [
        I(b(0x10, true)), // 0x00: .pdata function: bl 0x10
        I(blr()),
        D(0), // padding
        D(0),
        I(li(3, 1)), // 0x10: called
        I(blr()),
        I(li(3, 2)), // 0x18: found by the sweep
        I(blr()),
    ];
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 8, &routines);
    input.pdata = vec![at(0, 8)];
    let discovery = discover(&input).unwrap();
    assert_eq!(
        found(&discovery),
        [
            (0, 8, Source::Pdata),
            (0x10, 8, Source::Branch),
            (0x18, 8, Source::Sweep)
        ]
    );
    assert!(discovery.warnings.is_empty());
}

#[test]
fn overlapping_pdata_is_dropped_with_a_warning() {
    let words = [I(li(3, 1)), I(blr()), I(li(3, 2)), I(blr())];
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 4, &routines);
    input.pdata = vec![at(8, 8), at(0, 12)];
    let discovery = discover(&input).unwrap();
    // The last word is outside the range that stays, so the sweep takes it.
    assert_eq!(
        found(&discovery),
        [(0, 12, Source::Pdata), (12, 4, Source::Sweep)]
    );
    assert_eq!(
        discovery.warnings,
        [Warning::PdataOverlap {
            addr: BASE + 8,
            previous: BASE
        }]
    );
}

#[test]
fn a_call_into_a_pdata_function_is_a_second_entry_that_overlaps_it() {
    let words = [
        I(li(3, 1)), // 0x00: .pdata function with two entries
        I(b(0xC, false)),
        I(li(3, 2)), // 0x08: second entry, called from 0x18
        I(li(4, 0)),
        I(blr()), // 0x10: shared tail
        D(0),
        I(b(-0x10, true)), // 0x18: bl 0x08
        I(blr()),
    ];
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 8, &routines);
    input.pdata = vec![at(0, 0x14), at(0x18, 8)];
    let discovery = discover(&input).unwrap();
    assert_eq!(
        found(&discovery),
        [
            (0, 0x14, Source::Pdata),
            (8, 0xC, Source::SecondEntry),
            (0x18, 8, Source::Pdata)
        ]
    );
}

#[test]
fn exports_into_code_are_entries_and_into_data_are_not() {
    let words = [I(li(3, 1)), I(li(4, 1)), I(blr()), D(0x1234)];
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 3, &routines);
    // An export at 0x04 splits the code; the one into data is a variable.
    input.entries = vec![BASE + 4, BASE + 12];
    let discovery = discover(&input).unwrap();
    // The function at 0x00 runs into the entry at 0x04: a tail call, not a warning.
    assert_eq!(
        found(&discovery),
        [(0, 4, Source::Sweep), (4, 8, Source::Entry)]
    );
    assert!(discovery.warnings.is_empty());
}

#[test]
fn pointers_in_data_split_the_gaps_but_not_the_functions() {
    let words = [
        I(addi(3, 3, -4)), // 0x00: export, branches over the next one
        I(b(0xC, false)),
        I(addi(3, 3, -8)), // 0x08: only a vtable points here
        I(b(4, false)),
        I(li(4, 0)), // 0x10: the body both branch to
        I(blr()),
        I(blr()), // 0x18: .pdata function
        I(li(3, 0)),
        I(blr()),
        // Data: the vtable entry, a label inside the body, a pointer inside the .pdata function,
        // an unaligned value and a pointer into the data.
        D(BASE + 0x08),
        D(BASE + 0x14),
        D(BASE + 0x1C),
        D(BASE + 0x0A),
        D(BASE + 0x24),
    ];
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 9, &routines);
    input.entries = vec![BASE];
    input.pdata = vec![at(0x18, 0xC)];
    let discovery = discover(&input).unwrap();
    assert_eq!(
        found(&discovery),
        [
            (0, 8, Source::Entry),
            (8, 8, Source::Pointer),
            (0x10, 8, Source::Branch),
            (0x18, 0xC, Source::Pdata)
        ]
    );
}

#[test]
fn the_sweep_skips_padding_thunks_and_routines() {
    let words = [
        I(b(0x10, true)), // 0x00: bl to a thunk
        I(b(0x1C, true)), // 0x04: bl to a routine entry
        I(blr()),
        D(0),
        I(lis(11, -32000)), // 0x10: import thunk
        I(lwz(11, 0x10, 11)),
        I(mtctr(11)),
        I(bctr()),
        I(li(3, 1)), // 0x20: routine entry 0x20, end 0x24
        I(blr()),
        I(li(3, 2)), // 0x28: found by the sweep
        I(blr()),
    ];
    let bytes = bytes_of(&words);
    let mut routines = SaveRestore::new();
    let routine = Routine {
        family: Family::SaveGprLr,
        register: 31,
        end: BASE + 0x24,
    };
    routines.insert(BASE + 0x20, routine);
    let mut input = input(&bytes, 12, &routines);
    input.entries = vec![BASE];
    input.thunks = BTreeSet::from([BASE + 0x10]);
    input.pdata = vec![at(0x20, 8)];
    let discovery = discover(&input).unwrap();
    assert_eq!(
        found(&discovery),
        [
            (0, 0xC, Source::Entry),
            (0x20, 8, Source::Pdata),
            (0x28, 8, Source::Sweep)
        ]
    );
}

#[test]
fn a_call_to_a_function_that_never_returns_ends_a_function_of_the_sweep() {
    let words = [
        I(b(0x20, true)), // 0x00: export: bl longjmp
        I(li(3, 1)),      // 0x04: a new function, not part of the one before
        I(blr()),
        I(li(3, 9)), // 0x0C: calls longjmp on every path, so it never returns
        I(b(0x10, true)),
        I(b(-0x14, true)), // 0x14: export: bl 0x00, which never returns either
        I(li(3, 2)),       // 0x18
        I(blr()),
        I(blr()), // 0x20: longjmp
    ];
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 9, &routines);
    input.entries = vec![BASE, BASE + 0x14];
    input.longjmp = Some(BASE + 0x20);
    let discovery = discover(&input).unwrap();
    assert_eq!(
        found(&discovery),
        [
            (0, 4, Source::Entry),
            (4, 8, Source::Sweep),
            (0xC, 8, Source::Sweep),
            (0x14, 4, Source::Entry),
            (0x18, 8, Source::Sweep),
            (0x20, 4, Source::Branch)
        ]
    );
    let no_return: Vec<u32> = discovery.rules.no_return.iter().map(|a| a - BASE).collect();
    assert_eq!(no_return, [0, 0xC, 0x14, 0x20]);
}

#[test]
fn a_jump_table_keeps_its_cases_and_its_table_in_one_function() {
    let mut words = vec![I(cmplwi(6, 3, 1)), I(bgt(6, 0x24))];
    words.extend(load_address(12, BASE + 0x20).map(I));
    words.extend([slwi(0, 3, 2), lwzx(0, 12, 0), mtctr(0), bctr()].map(I));
    words.extend([D(BASE + 0x2C), D(BASE + 0x28)]); // 0x20: the table
    words.extend([I(li(3, 1)), I(blr())]); // 0x28, 0x2C: the cases
    words.extend([I(li(3, 2)), I(blr())]); // 0x30: found by the sweep
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 14, &routines);
    input.entries = vec![BASE];
    let discovery = discover(&input).unwrap();
    assert_eq!(
        found(&discovery),
        [(0, 0x30, Source::Entry), (0x30, 8, Source::Sweep)]
    );
    assert!(discovery.warnings.is_empty());
}

#[test]
fn unresolved_tables_targets_outside_and_falling_off_are_warnings() {
    // 0x00: a table without a bound check.
    let mut words: Vec<W> = load_address(12, BASE + 0x40).map(I).into();
    words.extend([slwi(0, 3, 2), lwzx(0, 12, 0), mtctr(0), bctr()].map(I));
    words.extend([
        I(b(0x1000, true)), // 0x18: export: a call outside the code
        I(li(3, 1)),        // 0x1C: then runs into the padding
        D(0),
    ]);
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 9, &routines);
    input.entries = vec![BASE, BASE + 0x18];
    let discovery = discover(&input).unwrap();
    assert_eq!(
        found(&discovery),
        [(0, 0x18, Source::Entry), (0x18, 8, Source::Entry)]
    );
    assert_eq!(
        discovery.warnings,
        [
            Warning::TargetOutsideCode {
                from: BASE + 0x18,
                target: BASE + 0x1018
            },
            Warning::UnresolvedJumpTable {
                function: BASE,
                bctr: BASE + 0x14
            },
            Warning::FallsOff {
                function: BASE + 0x18
            },
        ]
    );
}

#[test]
fn data_where_the_sweep_starts_is_skipped_and_an_entry_on_data_is_an_error() {
    // Primary opcode 1 is not assigned.
    let data = 0x0400_0000;
    assert_eq!(ferrum_decoder::decode(data), None);
    let words = [I(li(3, 1)), I(blr()), D(data), I(li(3, 2)), I(blr())];
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 5, &routines);
    input.entries = vec![BASE];
    let discovery = discover(&input).unwrap();
    assert_eq!(
        found(&discovery),
        [(0, 8, Source::Entry), (0xC, 8, Source::Sweep)]
    );
    input.entries = vec![BASE, BASE + 8];
    assert!(matches!(
        discover(&input),
        Err(Error::Undecodable { addr, .. }) if addr == BASE + 8
    ));
}

#[test]
fn overrides_replace_and_skip_remove() {
    let words = [
        I(li(3, 1)), // 0x00: .pdata says 8 bytes, the override 12
        I(li(4, 1)),
        I(blr()),
        D(0x1234_5678), // 0x0C: skipped
        D(0x9ABC_DEF0),
        I(li(3, 2)), // 0x14: found by the sweep
        I(blr()),
    ];
    let bytes = bytes_of(&words);
    let routines = SaveRestore::new();
    let mut input = input(&bytes, 7, &routines);
    input.pdata = vec![at(0, 8)];
    input.functions = vec![at(0, 12)];
    input.skip = vec![at(0xC, 8)];
    let discovery = discover(&input).unwrap();
    assert_eq!(
        found(&discovery),
        [(0, 12, Source::Override), (0x14, 8, Source::Sweep)]
    );
}
