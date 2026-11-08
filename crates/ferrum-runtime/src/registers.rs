// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The condition register and the fixed-point exception register.

/// The condition register: eight 4-bit fields, CR0 to CR7.
///
/// Each field lives in its own byte, with LT, GT, EQ and SO in bits 3 to 0, so that a compare
/// writes one byte and `mfcr`/`mtcrf` pack and unpack the 32-bit value. Field `n` and bit `bi` are
/// numbered as in the ISA: field 0 is the most significant nibble, and bit 0 is CR0's LT.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Cr {
    fields: [u8; 8],
}

impl Cr {
    /// The LT bit of a field: negative, or less than.
    pub const LT: u8 = 0b1000;
    /// The GT bit of a field: positive, or greater than.
    pub const GT: u8 = 0b0100;
    /// The EQ bit of a field: zero, or equal.
    pub const EQ: u8 = 0b0010;
    /// The SO bit of a field: a copy of XER\[SO\].
    pub const SO: u8 = 0b0001;

    /// Unpacks the 32-bit value that `mtcr` writes.
    pub const fn from_u32(value: u32) -> Self {
        let mut fields = [0; 8];
        let mut n = 0;
        while n < 8 {
            // The mask keeps one nibble, so the cast loses nothing.
            fields[n] = ((value >> (28 - 4 * n)) & 0xF) as u8;
            n += 1;
        }
        Self { fields }
    }

    /// Packs the fields into the 32-bit value that `mfcr` reads.
    pub const fn to_u32(self) -> u32 {
        let mut value = 0;
        let mut n = 0;
        while n < 8 {
            value |= (self.fields[n] as u32) << (28 - 4 * n);
            n += 1;
        }
        value
    }

    /// Returns field `n` (0 to 7) in its low four bits.
    pub fn field(&self, n: usize) -> u8 {
        self.fields[n]
    }

    /// Sets field `n` (0 to 7) to the low four bits of `value`.
    pub fn set_field(&mut self, n: usize, value: u8) {
        self.fields[n] = value & 0xF;
    }

    /// Returns the LT bit of field `n`.
    pub fn lt(&self, n: usize) -> bool {
        self.fields[n] & Self::LT != 0
    }

    /// Returns the GT bit of field `n`.
    pub fn gt(&self, n: usize) -> bool {
        self.fields[n] & Self::GT != 0
    }

    /// Returns the EQ bit of field `n`.
    // Named like the other bits and like the contract's `ctx.cr.eq(0)`. It hides `PartialEq::eq`
    // from method-call syntax only; `==` between two `Cr` still compares them.
    #[allow(clippy::should_implement_trait)]
    pub fn eq(&self, n: usize) -> bool {
        self.fields[n] & Self::EQ != 0
    }

    /// Returns the SO bit of field `n`.
    pub fn so(&self, n: usize) -> bool {
        self.fields[n] & Self::SO != 0
    }

    /// Sets field `n` as a compare instruction does: LT, GT or EQ from comparing `a` with `b`, and
    /// SO from `so`, the summary overflow bit of XER. The type of the operands says whether the
    /// comparison is signed or unsigned, and of how many bits.
    pub fn set_compare<T: Ord>(&mut self, n: usize, a: T, b: T, so: bool) {
        let order = match a.cmp(&b) {
            std::cmp::Ordering::Less => Self::LT,
            std::cmp::Ordering::Greater => Self::GT,
            std::cmp::Ordering::Equal => Self::EQ,
        };
        self.fields[n] = if so { order | Self::SO } else { order };
    }

    /// Returns bit `bi` (0 to 31) of the register, as the CR logical instructions and the
    /// conditional branches number it.
    pub fn bit(&self, bi: usize) -> bool {
        self.fields[bi / 4] & Self::mask(bi) != 0
    }

    /// Sets bit `bi` (0 to 31) of the register.
    pub fn set_bit(&mut self, bi: usize, value: bool) {
        let mask = Self::mask(bi);
        let field = &mut self.fields[bi / 4];
        if value {
            *field |= mask;
        } else {
            *field &= !mask;
        }
    }

    /// The mask of bit `bi` within its field: the first bit of a field is the most significant.
    fn mask(bi: usize) -> u8 {
        Self::LT >> (bi % 4)
    }
}

/// The fixed-point exception register.
///
/// Holds SO, OV, CA and the byte count of `lswx`/`stswx`. The other bits read as zero, and so does
/// the upper half of the 64-bit register, as `mfxer` returns it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Xer {
    /// Summary overflow: set by an overflow, cleared only by `mtxer`.
    pub so: bool,
    /// Overflow of the last instruction that records it.
    pub ov: bool,
    /// Carry out of the last instruction that records it.
    pub ca: bool,
    /// Bytes that `lswx` and `stswx` transfer, in the low seven bits.
    pub byte_count: u8,
}

impl Xer {
    const SO: u32 = 1 << 31;
    const OV: u32 = 1 << 30;
    const CA: u32 = 1 << 29;
    const BYTE_COUNT: u32 = 0x7F;

    /// Unpacks the low word of the value that `mtxer` writes.
    pub const fn from_u32(value: u32) -> Self {
        Self {
            so: value & Self::SO != 0,
            ov: value & Self::OV != 0,
            ca: value & Self::CA != 0,
            // The mask keeps seven bits, so the cast loses nothing.
            byte_count: (value & Self::BYTE_COUNT) as u8,
        }
    }

    /// Packs the register into the value that `mfxer` reads.
    pub const fn to_u32(self) -> u32 {
        let mut value = self.byte_count as u32 & Self::BYTE_COUNT;
        if self.so {
            value |= Self::SO;
        }
        if self.ov {
            value |= Self::OV;
        }
        if self.ca {
            value |= Self::CA;
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr_fields_are_nibbles_from_the_top() {
        let cr = Cr::from_u32(0x1234_5678);
        assert_eq!(
            (0..8).map(|n| cr.field(n)).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(cr.to_u32(), 0x1234_5678);
        for value in [0, u32::MAX, 0x8000_0000, 0x0000_0001, 0xA5A5_5A5A] {
            assert_eq!(Cr::from_u32(value).to_u32(), value);
        }
    }

    #[test]
    fn cr_set_field_keeps_four_bits() {
        let mut cr = Cr::default();
        cr.set_field(7, 0xFF);
        cr.set_field(0, Cr::EQ);
        assert_eq!(cr.to_u32(), 0x2000_000F);
        assert!(cr.eq(0) && !cr.lt(0) && !cr.gt(0) && !cr.so(0));
        assert!(cr.lt(7) && cr.gt(7) && cr.eq(7) && cr.so(7));
    }

    #[test]
    fn cr_bits_are_numbered_from_the_top() {
        for bi in 0..32 {
            let mut cr = Cr::default();
            cr.set_bit(bi, true);
            assert_eq!(cr.to_u32(), 0x8000_0000 >> bi, "bit {bi}");
            assert!(cr.bit(bi));
            cr.set_bit(bi, false);
            assert_eq!(cr.to_u32(), 0, "bit {bi}");
        }
        let cr = Cr::from_u32(0x8000_0001);
        assert!(cr.lt(0) && cr.bit(0) && cr.so(7) && cr.bit(31));
    }

    #[test]
    fn set_compare_orders_by_the_operand_type() {
        let mut cr = Cr::from_u32(0xFFFF_FFFF);
        cr.set_compare(0, -1i32, 0, false);
        cr.set_compare(1, u32::MAX, 0, false);
        cr.set_compare(2, 5u64, 5, true);
        cr.set_compare(7, 0i64, 1, true);
        assert_eq!(cr.to_u32(), 0x843F_FFF9);
    }

    #[test]
    fn xer_keeps_so_ov_ca_and_the_byte_count() {
        assert_eq!(
            Xer::from_u32(0x2000_0000),
            Xer {
                ca: true,
                ..Xer::default()
            }
        );
        assert_eq!(Xer::from_u32(0x8000_0000).to_u32(), 0x8000_0000);
        assert_eq!(Xer::from_u32(0x4000_0000).to_u32(), 0x4000_0000);
        assert_eq!(Xer::from_u32(0x0000_0055).byte_count, 0x55);
        // The reserved bits read as zero.
        assert_eq!(Xer::from_u32(u32::MAX).to_u32(), 0xE000_007F);
        let xer = Xer {
            byte_count: 0xFF,
            ..Xer::default()
        };
        assert_eq!(xer.to_u32(), 0x7F);
    }
}
