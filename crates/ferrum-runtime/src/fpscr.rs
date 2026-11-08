// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The floating-point status and control register.

use std::sync::Once;

use crate::ops::is_snan;

#[cfg(test)]
mod tests;

/// The floating-point status and control register, all 32 bits of it.
///
/// Bits are numbered as in the ISA, bit 0 being the most significant. The register holds whatever
/// the FPSCR instructions write, so `mffs` reads back any value `mtfsf` wrote. Of the bits that
/// other instructions set, the runtime computes FPCC (by the compares), the invalid-operation bits,
/// ZX, FX, VX and FEX; FPRF apart from FPCC, FR, FI, OX, UX and XX keep what the FPSCR
/// instructions last wrote. The enable bits have no effect: every exception takes the action the
/// ISA gives it when disabled. RN is kept but every operation rounds to nearest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Fpscr(u32);

impl Fpscr {
    /// Bit 0, FX: an exception bit went from 0 to 1. Sticky.
    pub const FX: u32 = 1 << 31;
    /// Bit 1, FEX: the OR of the exception bits whose enable bit is set.
    pub const FEX: u32 = 1 << 30;
    /// Bit 2, VX: the OR of the invalid-operation bits.
    pub const VX: u32 = 1 << 29;
    /// Bit 3, OX: overflow.
    pub const OX: u32 = 1 << 28;
    /// Bit 4, UX: underflow.
    pub const UX: u32 = 1 << 27;
    /// Bit 5, ZX: zero divide.
    pub const ZX: u32 = 1 << 26;
    /// Bit 6, XX: inexact.
    pub const XX: u32 = 1 << 25;
    /// Bit 7, VXSNAN: an operand was a signaling NaN.
    pub const VXSNAN: u32 = 1 << 24;
    /// Bit 8, VXISI: infinity minus infinity.
    pub const VXISI: u32 = 1 << 23;
    /// Bit 9, VXIDI: infinity divided by infinity.
    pub const VXIDI: u32 = 1 << 22;
    /// Bit 10, VXZDZ: zero divided by zero.
    pub const VXZDZ: u32 = 1 << 21;
    /// Bit 11, VXIMZ: infinity times zero.
    pub const VXIMZ: u32 = 1 << 20;
    /// Bit 12, VXVC: an ordered comparison with a NaN.
    pub const VXVC: u32 = 1 << 19;
    /// Bit 13, FR: the fraction was incremented when rounding.
    pub const FR: u32 = 1 << 18;
    /// Bit 14, FI: the result was inexact.
    pub const FI: u32 = 1 << 17;
    /// Bit 15, C: the class bit of FPRF.
    pub const C: u32 = 1 << 16;
    /// Bit 16, FL: less than, or negative.
    pub const FL: u32 = 1 << 15;
    /// Bit 17, FG: greater than, or positive.
    pub const FG: u32 = 1 << 14;
    /// Bit 18, FE: equal, or zero.
    pub const FE: u32 = 1 << 13;
    /// Bit 19, FU: unordered, or NaN.
    pub const FU: u32 = 1 << 12;
    /// Bit 21, VXSOFT: the software-defined condition.
    pub const VXSOFT: u32 = 1 << 10;
    /// Bit 22, VXSQRT: the square root of a negative number.
    pub const VXSQRT: u32 = 1 << 9;
    /// Bit 23, VXCVI: an integer conversion of a NaN or of a number out of range.
    pub const VXCVI: u32 = 1 << 8;
    /// Bit 24, VE: invalid operation enable.
    pub const VE: u32 = 1 << 7;
    /// Bit 25, OE: overflow enable.
    pub const OE: u32 = 1 << 6;
    /// Bit 26, UE: underflow enable.
    pub const UE: u32 = 1 << 5;
    /// Bit 27, ZE: zero divide enable.
    pub const ZE: u32 = 1 << 4;
    /// Bit 28, XE: inexact enable.
    pub const XE: u32 = 1 << 3;
    /// Bit 29, NI: non-IEEE mode.
    pub const NI: u32 = 1 << 2;
    /// Bits 30:31, RN: the rounding mode, `0b00` being round to nearest.
    pub const RN: u32 = 0b11;
    /// FPCC, bits 16:19.
    pub const FPCC: u32 = Self::FL | Self::FG | Self::FE | Self::FU;

    /// The invalid-operation bits, which VX summarizes.
    const INVALID: u32 = Self::VXSNAN
        | Self::VXISI
        | Self::VXIDI
        | Self::VXZDZ
        | Self::VXIMZ
        | Self::VXVC
        | Self::VXSOFT
        | Self::VXSQRT
        | Self::VXCVI;
    /// The sticky exception bits, bits 3:12 and 21:23.
    const EXCEPTIONS: u32 = Self::OX | Self::UX | Self::ZX | Self::XX | Self::INVALID;

    /// Returns the register holding `value` as it is, the summary bits included.
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the 32 bits of the register.
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// Returns RN, the rounding mode the guest last wrote.
    pub const fn rounding_mode(self) -> u8 {
        // The mask keeps two bits, so the cast loses nothing.
        (self.0 & Self::RN) as u8
    }

    /// Returns what a record form (Rc=1) puts in CR1: bits 0:3, FX, FEX, VX and OX.
    pub const fn record(self) -> u8 {
        // The shift leaves four bits.
        (self.0 >> 28) as u8
    }

    /// `mffs`: the register in the low word of an FPR. The ISA leaves the high word undefined;
    /// it is zero here.
    pub fn mffs(self) -> f64 {
        f64::from_bits(u64::from(self.0))
    }

    /// `mtfsf`: the fields that `flm` selects (bit 0x80 for field 0) take their value from the
    /// low word of `frb`. FX changes only through field 0; FEX and VX are recomputed, never
    /// taken from `frb`.
    pub fn mtfsf(&mut self, flm: u8, frb: f64) {
        let mut mask = 0;
        for field in 0..8 {
            if flm & (0x80 >> field) != 0 {
                mask |= field_mask(field);
            }
        }
        // The low word of the FPR is the value; the truncation is the definition.
        let value = frb.to_bits() as u32;
        self.write(mask, value);
    }

    /// `mtfsfi`: field `bf` (0 to 7) takes the four bits of `u`.
    pub fn mtfsfi(&mut self, bf: u8, u: u8) {
        let field = u32::from(bf);
        self.write(field_mask(field), u32::from(u & 0xF) << (28 - 4 * field));
    }

    /// `mtfsb0`: clears bit `bt` (0 to 31). FEX and VX cannot be cleared this way.
    pub fn mtfsb0(&mut self, bt: u8) {
        let bit = bit(bt);
        self.write(bit, 0);
    }

    /// `mtfsb1`: sets bit `bt` (0 to 31), and FX if that bit is an exception bit that was 0. FEX
    /// and VX cannot be set this way.
    pub fn mtfsb1(&mut self, bt: u8) {
        let bit = bit(bt);
        let rises = bit & Self::EXCEPTIONS & !self.0 != 0;
        self.write(bit, bit);
        if rises {
            self.0 |= Self::FX;
        }
    }

    /// `mcrfs`: returns field `bfa` (0 to 7) for the CR, and clears the exception bits of that
    /// field, and FX if it is in it.
    pub fn mcrfs(&mut self, bfa: u8) -> u8 {
        let field = u32::from(bfa);
        // The shift and mask leave four bits.
        let value = ((self.0 >> (28 - 4 * field)) & 0xF) as u8;
        let clear = field_mask(field) & (Self::EXCEPTIONS | Self::FX);
        self.0 &= !clear;
        self.summarize();
        value
    }

    /// `fcmpu`: compares `a` with `b`, sets FPCC, and returns the field for the CR: LT, GT or EQ,
    /// or unordered (the SO position) if either is a NaN. A signaling NaN sets VXSNAN.
    pub fn fcmpu(&mut self, a: f64, b: f64) -> u8 {
        let order = order(a, b);
        if is_snan(a) || is_snan(b) {
            self.raise(Self::VXSNAN);
        }
        self.set_fpcc(order);
        order
    }

    /// `fcmpo`: compares as [`Fpscr::fcmpu`] does. A NaN also sets VXVC, a signaling one with
    /// VXSNAN, as it does with invalid operation disabled.
    pub fn fcmpo(&mut self, a: f64, b: f64) -> u8 {
        let order = order(a, b);
        if is_snan(a) || is_snan(b) {
            self.raise(Self::VXSNAN | Self::VXVC);
        } else if a.is_nan() || b.is_nan() {
            self.raise(Self::VXVC);
        }
        self.set_fpcc(order);
        order
    }

    /// Sets exception bits, and FX if any of them was 0, then recomputes VX and FEX.
    pub(crate) fn raise(&mut self, bits: u32) {
        let rises = bits & Self::EXCEPTIONS & !self.0 != 0;
        self.0 |= bits;
        if rises {
            self.0 |= Self::FX;
        }
        self.summarize();
    }

    /// Writes the bits of `mask` from `value`, except FEX and VX, which are recomputed. Warns
    /// once per process if RN is left non-zero.
    fn write(&mut self, mask: u32, value: u32) {
        let mask = mask & !(Self::FEX | Self::VX);
        self.0 = (self.0 & !mask) | (value & mask);
        self.summarize();
        if self.0 & Self::RN != 0 {
            rounding_mode_warning(self.rounding_mode());
        }
    }

    /// Recomputes VX and FEX from the bits they summarize.
    fn summarize(&mut self) {
        let bits = self.0;
        let vx = bits & Self::INVALID != 0;
        let enabled = |exception: u32, enable: u32| bits & exception != 0 && bits & enable != 0;
        let fex = (vx && bits & Self::VE != 0)
            || enabled(Self::OX, Self::OE)
            || enabled(Self::UX, Self::UE)
            || enabled(Self::ZX, Self::ZE)
            || enabled(Self::XX, Self::XE);
        self.0 &= !(Self::VX | Self::FEX);
        if vx {
            self.0 |= Self::VX;
        }
        if fex {
            self.0 |= Self::FEX;
        }
    }

    fn set_fpcc(&mut self, order: u8) {
        self.0 = (self.0 & !Self::FPCC) | (u32::from(order) << 12);
    }
}

/// The mask of FPSCR field `field` (0 to 7), field 0 being the most significant nibble.
fn field_mask(field: u32) -> u32 {
    0xF << (28 - 4 * field)
}

/// The mask of FPSCR bit `bt` (0 to 31), numbered from the most significant.
fn bit(bt: u8) -> u32 {
    1 << (31 - u32::from(bt & 0x1F))
}

/// The CR field of a floating-point compare: `0b1000` less, `0b0100` greater, `0b0010` equal,
/// `0b0001` unordered. ±0 compare equal.
fn order(a: f64, b: f64) -> u8 {
    match a.partial_cmp(&b) {
        Some(std::cmp::Ordering::Less) => 0b1000,
        Some(std::cmp::Ordering::Greater) => 0b0100,
        Some(std::cmp::Ordering::Equal) => 0b0010,
        None => 0b0001,
    }
}

/// Prints, once per process, that the guest asked for a rounding mode the runtime does not have.
#[cold]
#[inline(never)]
fn rounding_mode_warning(rn: u8) {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "warning: ferrum-runtime: the guest set FPSCR[RN] to {rn:#04b}; only round to nearest \
             is supported, so floating-point results keep rounding to nearest"
        );
    });
}
