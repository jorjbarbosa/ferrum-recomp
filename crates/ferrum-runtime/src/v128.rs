// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The value of a 128-bit vector register.

/// A 128-bit vector, as four 32-bit lanes in PPC order.
///
/// Lane 0 holds bits 0..31, the most significant word, which is also the word at the lowest
/// address when the vector is in memory. [`crate::Memory`] loads and stores each lane as a
/// big-endian word, so a vector is never byte-reversed as a whole.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct V128(pub [u32; 4]);

impl V128 {
    /// The vector with every bit clear.
    pub const ZERO: Self = Self([0; 4]);

    /// Builds a vector from its upper doubleword (lanes 0 and 1) and its lower one (lanes 2 and 3).
    pub const fn from_halves(high: u64, low: u64) -> Self {
        // Each `as u32` keeps the low word of a doubleword on purpose; the shifts bring down the
        // high words.
        Self([
            (high >> 32) as u32,
            high as u32,
            (low >> 32) as u32,
            low as u32,
        ])
    }

    /// Returns the upper doubleword (lanes 0 and 1) and the lower one (lanes 2 and 3).
    pub const fn halves(self) -> (u64, u64) {
        let [l0, l1, l2, l3] = self.0;
        (
            ((l0 as u64) << 32) | l1 as u64,
            ((l2 as u64) << 32) | l3 as u64,
        )
    }

    /// Builds a vector from its 16 bytes in memory order: byte element 0 is the most significant.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self::from_u128(u128::from_be_bytes(bytes))
    }

    /// Returns the 16 bytes in memory order: byte element 0 first.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.to_u128().to_be_bytes()
    }

    /// Builds a vector from its eight halfword elements, element 0 being the most significant.
    pub fn from_halfwords(halfwords: [u16; 8]) -> Self {
        Self(std::array::from_fn(|i| {
            (u32::from(halfwords[2 * i]) << 16) | u32::from(halfwords[2 * i + 1])
        }))
    }

    /// Returns the eight halfword elements, element 0 first.
    pub fn halfwords(self) -> [u16; 8] {
        // Each cast keeps one half of a word on purpose.
        std::array::from_fn(|i| (self.0[i / 2] >> (16 * (1 - i % 2))) as u16)
    }

    /// Builds a vector from the 128-bit integer whose most significant bits are lane 0.
    pub const fn from_u128(value: u128) -> Self {
        let (high, low) = ((value >> 64) as u64, value as u64);
        Self::from_halves(high, low)
    }

    /// Returns the vector as a 128-bit integer, lane 0 in the most significant bits.
    pub const fn to_u128(self) -> u128 {
        let (high, low) = self.halves();
        ((high as u128) << 64) | low as u128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_zero_is_the_most_significant_word() {
        let v = V128::from_halves(0x0011_2233_4455_6677, 0x8899_AABB_CCDD_EEFF);
        assert_eq!(v.0, [0x0011_2233, 0x4455_6677, 0x8899_AABB, 0xCCDD_EEFF]);
        assert_eq!(v.halves(), (0x0011_2233_4455_6677, 0x8899_AABB_CCDD_EEFF));
    }

    #[test]
    fn bytes_and_halfwords_count_from_the_most_significant() {
        let v = V128([0x0011_2233, 0x4455_6677, 0x8899_AABB, 0xCCDD_EEFF]);
        let bytes: [u8; 16] = std::array::from_fn(|i| 0x11 * i as u8);
        assert_eq!(v.to_bytes(), bytes);
        assert_eq!(V128::from_bytes(bytes), v);
        let halfwords = [
            0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xAABB, 0xCCDD, 0xEEFF,
        ];
        assert_eq!(v.halfwords(), halfwords);
        assert_eq!(V128::from_halfwords(halfwords), v);
        assert_eq!(v.to_u128(), 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF);
        assert_eq!(V128::from_u128(v.to_u128()), v);
    }
}
