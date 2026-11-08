// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The FPSCR instructions and compares, from 4.2.2, 4.6.7 and 4.6.8 of Book I.

use super::*;

const SNAN: f64 = f64::from_bits(0x7FF0_0000_0000_0001);
const QNAN: f64 = f64::from_bits(0x7FF8_0000_0000_0000);

#[test]
fn the_register_keeps_every_bit_and_mffs_puts_it_in_the_low_word() {
    let fpscr = Fpscr::from_u32(0xFFFF_FFFF);
    assert_eq!(fpscr.to_u32(), 0xFFFF_FFFF);
    assert_eq!(fpscr.mffs().to_bits(), 0x0000_0000_FFFF_FFFF);
    assert_eq!(fpscr.rounding_mode(), 3);
    assert_eq!(fpscr.record(), 0xF);
    assert_eq!(Fpscr::from_u32(0x9000_0000).record(), 0b1001);
}

#[test]
fn the_bits_are_numbered_from_the_top() {
    // A few by their ISA numbers: FX 0, VXSNAN 7, VXVC 12, FPCC 16:19, VXCVI 23, VE 24, RN 30:31.
    assert_eq!(Fpscr::FX, 0x8000_0000);
    assert_eq!(Fpscr::VXSNAN, 0x0100_0000);
    assert_eq!(Fpscr::VXVC, 0x0008_0000);
    assert_eq!(Fpscr::FPCC, 0x0000_F000);
    assert_eq!(Fpscr::VXCVI, 0x0000_0100);
    assert_eq!(Fpscr::VE, 0x0000_0080);
    assert_eq!(Fpscr::RN, 0x0000_0003);
}

#[test]
fn an_exception_sets_fx_only_when_it_is_new() {
    let mut fpscr = Fpscr::default();
    fpscr.raise(Fpscr::VXSNAN);
    assert_eq!(fpscr.to_u32(), Fpscr::FX | Fpscr::VX | Fpscr::VXSNAN);
    fpscr.mtfsb0(0);
    fpscr.raise(Fpscr::VXSNAN);
    assert_eq!(fpscr.to_u32(), Fpscr::VX | Fpscr::VXSNAN, "not new");
    fpscr.raise(Fpscr::ZX);
    assert_eq!(
        fpscr.to_u32(),
        Fpscr::FX | Fpscr::VX | Fpscr::VXSNAN | Fpscr::ZX
    );
}

#[test]
fn fex_is_the_or_of_the_enabled_exceptions() {
    let mut fpscr = Fpscr::from_u32(Fpscr::VE);
    fpscr.raise(Fpscr::VXISI);
    assert_eq!(
        fpscr.to_u32(),
        Fpscr::FX | Fpscr::FEX | Fpscr::VX | Fpscr::VXISI | Fpscr::VE
    );
    let mut fpscr = Fpscr::from_u32(Fpscr::OE);
    fpscr.raise(Fpscr::ZX);
    assert_eq!(fpscr.to_u32() & Fpscr::FEX, 0, "ZX is not enabled");
    fpscr.mtfsb1(27); // ZE
    assert_ne!(fpscr.to_u32() & Fpscr::FEX, 0, "now it is");
}

#[test]
fn mtfsf_writes_the_selected_fields_and_recomputes_the_summaries() {
    let mut fpscr = Fpscr::default();
    // FEX and VX are never taken from the source (4.6.8).
    fpscr.mtfsf(0xFF, f64::from_bits(0x6000_0000));
    assert_eq!(fpscr.to_u32(), 0);
    // Field 0 takes FX and OX from the source.
    fpscr.mtfsf(0x80, f64::from_bits(0xF000_0000));
    assert_eq!(fpscr.to_u32(), Fpscr::FX | Fpscr::OX);
    // Field 1 (UX ZX XX VXSNAN): VX follows VXSNAN, but FX does not change, though exception
    // bits went from 0 to 1.
    let mut fpscr = Fpscr::default();
    fpscr.mtfsf(0x40, f64::from_bits(0x0F00_0000));
    assert_eq!(fpscr.to_u32(), 0x2F00_0000);
    // Unselected fields stay; the high word of the source is ignored.
    let mut fpscr = Fpscr::from_u32(0x0000_00F8);
    fpscr.mtfsf(0x01, f64::from_bits(0xFFFF_FFFF_0000_0001));
    assert_eq!(
        fpscr.to_u32(),
        0x0000_00F1,
        "field 7 (XE NI RN) changes, field 6 stays"
    );
    assert_eq!(fpscr.rounding_mode(), 1);
}

#[test]
fn mtfsfi_writes_one_field() {
    let mut fpscr = Fpscr::default();
    fpscr.mtfsfi(7, 0b0010);
    assert_eq!(fpscr.rounding_mode(), 2);
    // In field 0, FX and OX come from U, FEX and VX do not (4.6.8).
    fpscr.mtfsfi(0, 0b1111);
    assert_eq!(fpscr.to_u32(), Fpscr::FX | Fpscr::OX | 0b10);
    fpscr.mtfsfi(0, 0);
    fpscr.mtfsfi(7, 0);
    assert_eq!(fpscr.to_u32(), 0);
}

#[test]
fn mtfsb_changes_one_bit_but_never_the_summaries() {
    let mut fpscr = Fpscr::default();
    fpscr.mtfsb1(1);
    fpscr.mtfsb1(2);
    assert_eq!(fpscr.to_u32(), 0, "FEX and VX cannot be set");
    // An exception bit that was 0 sets FX too.
    fpscr.mtfsb1(7);
    assert_eq!(fpscr.to_u32(), Fpscr::FX | Fpscr::VX | Fpscr::VXSNAN);
    fpscr.mtfsb0(2);
    assert_eq!(
        fpscr.to_u32(),
        Fpscr::FX | Fpscr::VX | Fpscr::VXSNAN,
        "VX cannot be cleared while VXSNAN is set"
    );
    fpscr.mtfsb0(7);
    assert_eq!(fpscr.to_u32(), Fpscr::FX);
    fpscr.mtfsb0(0);
    // A control bit does not set FX.
    fpscr.mtfsb1(24);
    assert_eq!(fpscr.to_u32(), Fpscr::VE);
    fpscr.mtfsb1(31);
    assert_eq!(fpscr.rounding_mode(), 1);
}

#[test]
fn mcrfs_copies_a_field_and_clears_its_exception_bits() {
    let all = Fpscr::from_u32(0xFFFF_FFFF);
    let after = |field: u8| {
        let mut fpscr = all;
        let value = fpscr.mcrfs(field);
        (value, fpscr.to_u32())
    };
    // Field 0: FX and OX are cleared; FEX and VX stay, being summaries of bits still set.
    assert_eq!(after(0), (0xF, 0x6FFF_FFFF));
    // Field 1: UX, ZX, XX and VXSNAN.
    assert_eq!(after(1), (0xF, 0xF0FF_FFFF));
    // Field 3: only VXVC is an exception bit; FR, FI and C stay.
    assert_eq!(after(3), (0xF, 0xFFF7_FFFF));
    // Field 4 is FPCC, field 6 the enables: nothing is cleared.
    assert_eq!(after(4), (0xF, 0xFFFF_FFFF));
    assert_eq!(after(6), (0xF, 0xFFFF_FFFF));
    // Field 5: bit 20 is reserved and stays; VXSOFT, VXSQRT and VXCVI go.
    assert_eq!(after(5), (0xF, 0xFFFF_F8FF));
    // Clearing the last invalid-operation bits clears VX.
    let mut fpscr = Fpscr::default();
    fpscr.raise(Fpscr::VXSNAN);
    assert_eq!(fpscr.mcrfs(1), 0b0001);
    assert_eq!(fpscr.to_u32(), Fpscr::FX);
}

#[test]
fn compares_set_fpcc_and_return_the_cr_field() {
    let mut fpscr = Fpscr::from_u32(Fpscr::C);
    assert_eq!(fpscr.fcmpu(1.0, 2.0), 0b1000);
    assert_eq!(fpscr.to_u32(), Fpscr::C | Fpscr::FL, "C is left alone");
    assert_eq!(fpscr.fcmpu(2.0, 1.0), 0b0100);
    assert_eq!(fpscr.fcmpu(0.0, -0.0), 0b0010, "±0 are equal");
    assert_eq!(fpscr.fcmpu(f64::INFINITY, f64::INFINITY), 0b0010);
    assert_eq!(fpscr.fcmpu(f64::NEG_INFINITY, f64::from_bits(1)), 0b1000);
    assert_eq!(fpscr.fcmpu(QNAN, 1.0), 0b0001, "unordered");
    assert_eq!(
        fpscr.to_u32(),
        Fpscr::C | Fpscr::FU,
        "a quiet NaN raises nothing"
    );
    assert_eq!(fpscr.fcmpu(1.0, SNAN), 0b0001);
    assert_eq!(
        fpscr.to_u32(),
        Fpscr::C | Fpscr::FU | Fpscr::FX | Fpscr::VX | Fpscr::VXSNAN
    );
}

#[test]
fn an_ordered_compare_with_a_nan_is_invalid() {
    let mut fpscr = Fpscr::default();
    assert_eq!(fpscr.fcmpo(1.0, 1.0), 0b0010);
    assert_eq!(fpscr.to_u32(), Fpscr::FE);
    assert_eq!(fpscr.fcmpo(QNAN, 1.0), 0b0001);
    assert_eq!(
        fpscr.to_u32(),
        Fpscr::FU | Fpscr::FX | Fpscr::VX | Fpscr::VXVC
    );
    let mut fpscr = Fpscr::default();
    assert_eq!(fpscr.fcmpo(1.0, SNAN), 0b0001);
    assert_eq!(
        fpscr.to_u32(),
        Fpscr::FU | Fpscr::FX | Fpscr::VX | Fpscr::VXVC | Fpscr::VXSNAN
    );
}
