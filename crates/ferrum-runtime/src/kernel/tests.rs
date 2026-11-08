// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

use super::*;
use crate::fn_table::GuestFn;
use crate::test_support::memory;

/// Builds the `Kernels` of a test from a kernel that implements both libraries.
fn kernels<'a, K: Xboxkrnl + Xam>(kernel: &'a K, table: &'a FnTable) -> Kernels<'a> {
    Kernels {
        krnl: kernel,
        xam: kernel,
        table,
        hooks: crate::HookTable::empty(),
    }
}

#[test]
#[should_panic(expected = "unimplemented variable import: XboxHardwareInfo of xboxkrnl.exe")]
fn an_unimplemented_variable_panics_with_its_name() {
    Xboxkrnl::resolve_variable(&Unimplemented, "XboxHardwareInfo");
}

#[test]
#[should_panic(expected = "unimplemented import: ordinal 4660 of xam.xex @ LR=0x82001018")]
fn an_unnamed_import_panics_with_its_ordinal_and_lr() {
    let table = FnTable::new();
    let mut ctx = PpcContext::new();
    ctx.lr = 0x8200_1018;
    Xam::unnamed_import(
        &Unimplemented,
        0x1234,
        &mut ctx,
        memory(),
        &kernels(&Unimplemented, &table),
    );
}

/// A kernel that implements one thing: `resolve_variable` of xboxkrnl, and an unnamed import that
/// starts the guest function whose address is in r3, as a thread start would.
struct OneImport;

impl Xboxkrnl for OneImport {
    fn resolve_variable(&self, name: &str) -> u32 {
        match name {
            "XboxHardwareInfo" => 0x8000_1000,
            _ => 0,
        }
    }

    fn unnamed_import(&self, _: u16, ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {
        // r3 holds a guest address; truncating the register to 32 bits is how the guest uses it.
        let start = ctx.r[3] as u32;
        (k.table.lookup(start, ctx.lr))(ctx, mem, k);
    }
}

impl Xam for OneImport {}

fn guest_thread(ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
    ctx.r[4] = 0x5EED;
}

#[test]
fn a_port_overrides_only_what_it_needs_and_can_call_back_into_the_guest() {
    static FUNCTIONS: [Option<GuestFn>; 1] = [Some(guest_thread)];
    let mut table = FnTable::new();
    table.register(0x8200_0000, &FUNCTIONS).unwrap();
    let k = kernels(&OneImport, &table);
    assert_eq!(k.krnl.resolve_variable("XboxHardwareInfo"), 0x8000_1000);

    let mut ctx = PpcContext::new();
    ctx.r[3] = 0x8200_0000;
    k.krnl.unnamed_import(1, &mut ctx, memory(), &k);
    assert_eq!(ctx.r[4], 0x5EED);
}

#[test]
#[should_panic(expected = "unimplemented import: ordinal 7 of xam.xex")]
fn what_a_port_does_not_override_still_panics() {
    let table = FnTable::new();
    let k = kernels(&OneImport, &table);
    k.xam
        .unnamed_import(7, &mut PpcContext::new(), memory(), &k);
}

#[test]
#[should_panic(expected = "unimplemented import: NtCreateFile @ LR=0x82001018")]
fn a_named_import_panics_with_its_name_and_lr() {
    let table = FnTable::new();
    let mut ctx = PpcContext::new();
    ctx.lr = 0x8200_1018;
    let k = kernels(&Unimplemented, &table);
    k.krnl.NtCreateFile(&mut ctx, memory(), &k);
}

#[test]
#[should_panic(expected = "unimplemented import: XamUserGetName @ LR=0x00000000")]
fn the_xam_trait_has_its_own_functions() {
    let table = FnTable::new();
    let k = kernels(&Unimplemented, &table);
    k.xam.XamUserGetName(&mut PpcContext::new(), memory(), &k);
}

/// A kernel that implements one named function and nothing else.
struct CreatesFiles;

impl Xboxkrnl for CreatesFiles {
    fn NtCreateFile(&self, ctx: &mut PpcContext, _: &Memory, _: &Kernels<'_>) {
        // STATUS_SUCCESS
        ctx.r[3] = 0;
    }
}

impl Xam for CreatesFiles {}

#[test]
fn a_port_implements_a_named_import() {
    let table = FnTable::new();
    let k = kernels(&CreatesFiles, &table);
    let mut ctx = PpcContext::new();
    ctx.r[3] = 0xFFFF_FFFF;
    k.krnl.NtCreateFile(&mut ctx, memory(), &k);
    assert_eq!(ctx.r[3], 0);
}
