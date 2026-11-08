// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::*;
use crate::kernel::Unimplemented;
use crate::test_support::memory;

// Each guest function leaves a different value in r3, so a test can tell which one ran without
// comparing function pointers, which the compiler may merge.
fn returns_1(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
    ctx.r[3] = 1;
}
fn returns_2(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
    ctx.r[3] = 2;
}
fn returns_3(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
    ctx.r[3] = 3;
}
fn returns_4(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
    ctx.r[3] = 4;
}

const CODE: u32 = 0x8200_0000;
static CODE_FUNCTIONS: [Option<GuestFn>; 4] =
    [Some(returns_1), None, Some(returns_2), Some(returns_3)];
const MODULE: u32 = 0x9000_0000;
static MODULE_FUNCTIONS: [Option<GuestFn>; 1] = [Some(returns_4)];

/// A table with two modules: `CODE_FUNCTIONS` at `CODE` and `MODULE_FUNCTIONS` at `MODULE`.
fn two_modules() -> FnTable {
    let mut table = FnTable::new();
    table.register(CODE, &CODE_FUNCTIONS).unwrap();
    table.register(MODULE, &MODULE_FUNCTIONS).unwrap();
    table
}

/// Calls the function at `addr` through `table` and returns the r3 it leaves.
fn call(table: &FnTable, addr: u32) -> u64 {
    let k = Kernels {
        krnl: &Unimplemented,
        xam: &Unimplemented,
        table,
        hooks: crate::HookTable::empty(),
    };
    let mut ctx = PpcContext::new();
    (table.lookup(addr, 0))(&mut ctx, memory(), &k);
    ctx.r[3]
}

#[test]
fn each_address_finds_its_own_function() {
    let table = two_modules();
    assert_eq!(call(&table, CODE), 1);
    assert_eq!(call(&table, CODE + 8), 2);
    assert_eq!(call(&table, CODE + 12), 3);
    assert_eq!(call(&table, MODULE), 4);
}

#[test]
fn addresses_without_a_function_find_nothing() {
    let table = two_modules();
    for addr in [
        CODE - 4,
        CODE + 4,
        CODE + 2,
        CODE + 16,
        MODULE + 4,
        MODULE - 4,
        0,
        u32::MAX,
    ] {
        assert!(table.get(addr).is_none(), "{addr:#x}");
    }
    assert!(FnTable::new().get(CODE).is_none());
}

#[test]
#[should_panic(expected = "no guest function at 0x82000004 (LR=0x82001018)")]
fn lookup_panics_with_the_address_and_lr() {
    two_modules().lookup(CODE + 4, 0x8200_1018);
}

#[test]
fn register_rejects_a_misaligned_base() {
    let mut table = FnTable::new();
    let error = table.register(CODE + 2, &CODE_FUNCTIONS).unwrap_err();
    assert!(matches!(error, Error::MisalignedRange { base } if base == CODE + 2));
}

#[test]
fn register_rejects_a_range_past_the_address_space() {
    static TWO: [Option<GuestFn>; 2] = [None, Some(returns_1)];
    let mut table = FnTable::new();
    let error = table.register(0xFFFF_FFFC, &TWO).unwrap_err();
    assert!(matches!(
        error,
        Error::RangeOverflow {
            base: 0xFFFF_FFFC,
            len: 2
        }
    ));
    // Ending exactly at 4 GiB is fine.
    table.register(0xFFFF_FFF8, &TWO).unwrap();
    assert_eq!(call(&table, 0xFFFF_FFFC), 1);
}

#[test]
fn register_rejects_overlapping_ranges_but_not_adjacent_ones() {
    let mut table = two_modules();
    for base in [CODE, CODE - 4, CODE + 12, MODULE - 12] {
        let error = table.register(base, &CODE_FUNCTIONS).unwrap_err();
        assert!(
            matches!(error, Error::OverlappingRange { .. }),
            "{base:#x}: {error}"
        );
    }
    table.register(CODE - 16, &CODE_FUNCTIONS).unwrap();
    table.register(CODE + 16, &CODE_FUNCTIONS).unwrap();
    assert_eq!(call(&table, CODE - 16), 1);
    assert_eq!(call(&table, CODE + 16 + 12), 3);
    assert_eq!(call(&table, CODE + 12), 3);
}

/// A list of entries for `FnTable::register_entries`.
type Entries<'a> = &'a [(u32, GuestFn)];

#[test]
fn register_entries_builds_a_dense_range_from_lists() {
    let mut table = FnTable::new();
    let first: Entries<'_> = &[(CODE + 8, returns_2)];
    let second: Entries<'_> = &[(CODE, returns_1), (CODE + 12, returns_3)];
    table.register_entries(CODE, 5, &[first, second]).unwrap();
    assert_eq!(call(&table, CODE), 1);
    assert_eq!(call(&table, CODE + 8), 2);
    assert_eq!(call(&table, CODE + 12), 3);
    for addr in [CODE - 4, CODE + 4, CODE + 16, CODE + 20] {
        assert!(table.get(addr).is_none(), "{addr:#x}");
    }
    // The range covers its five words even where no function starts.
    let error = table.register(CODE + 16, &CODE_FUNCTIONS).unwrap_err();
    assert!(matches!(error, Error::OverlappingRange { .. }), "{error}");
}

#[test]
fn register_entries_rejects_entries_the_range_cannot_hold() {
    let cases: [(Entries<'_>, u32, &str); 4] = [
        (&[(CODE + 2, returns_1)], CODE + 2, "is not 4-aligned"),
        (
            &[(CODE + 16, returns_1)],
            CODE + 16,
            "lies outside its range",
        ),
        (&[(CODE - 4, returns_1)], CODE - 4, "lies outside its range"),
        (
            &[(CODE + 4, returns_1), (CODE + 4, returns_2)],
            CODE + 4,
            "repeats an address",
        ),
    ];
    for (list, expected, why) in cases {
        let mut table = FnTable::new();
        let error = table.register_entries(CODE, 4, &[list]).unwrap_err();
        assert!(
            matches!(error, Error::InvalidEntry { addr, why: w } if addr == expected && w == why),
            "{error}"
        );
        assert!(table.get(CODE).is_none(), "nothing was registered");
    }
    // An address repeated across two lists is caught too.
    let mut table = FnTable::new();
    let list: Entries<'_> = &[(CODE, returns_1)];
    let error = table.register_entries(CODE, 4, &[list, list]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "the function entry at 0x82000000 repeats an address"
    );
}

#[test]
fn register_entries_checks_its_range_as_register_does() {
    let mut table = two_modules();
    let error = table.register_entries(CODE + 2, 1, &[]).unwrap_err();
    assert!(matches!(error, Error::MisalignedRange { .. }), "{error}");
    let error = table
        .register_entries(0xFFFF_FFFC, usize::MAX, &[])
        .unwrap_err();
    assert!(matches!(error, Error::RangeOverflow { .. }), "{error}");
    let error = table.register_entries(CODE + 12, 1, &[]).unwrap_err();
    assert!(matches!(error, Error::OverlappingRange { .. }), "{error}");
    table.register_entries(CODE + 16, 1, &[]).unwrap();
}

#[test]
fn set_replaces_an_entry_inside_a_range_and_nothing_else() {
    let mut table = two_modules();
    assert_eq!(call(&table, CODE), 1);
    table.set(CODE, returns_4).unwrap();
    assert_eq!(call(&table, CODE), 4, "the entry was replaced");
    // An empty slot of a range takes a function too, and the borrowed list is left alone.
    table.set(CODE + 4, returns_3).unwrap();
    assert_eq!(call(&table, CODE + 4), 3);
    assert!(CODE_FUNCTIONS[1].is_none());
    assert_eq!(call(&two_modules(), CODE), 1);
    assert!(matches!(
        table.set(CODE + 2, returns_3),
        Err(Error::InvalidEntry {
            why: "is not 4-aligned",
            ..
        })
    ));
    assert!(matches!(
        table.set(0x1000, returns_3),
        Err(Error::InvalidEntry {
            why: "lies in no registered range",
            ..
        })
    ));
}
