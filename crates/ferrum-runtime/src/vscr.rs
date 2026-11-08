// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The vector status and control register.

use crate::V128;

/// The vector status and control register: NJ and SAT, the two bits the ISA defines.
///
/// The other bits are reserved, so the register keeps only these two and reads the rest as zero.
/// NJ selects non-Java mode, in which the vector floating-point helpers of [`crate::ops`] flush
/// denormals; SAT records that a saturating instruction saturated, and stays set until an
/// `mtvscr` clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vscr(u32);

impl Vscr {
    /// NJ, bit 111 of the 128-bit register (bit 15 of the word): non-Java mode.
    pub const NJ: u32 = 0x0001_0000;
    /// SAT, bit 127 of the 128-bit register (bit 31 of the word): saturation. Sticky.
    pub const SAT: u32 = 0x0000_0001;

    /// Returns the register holding the NJ and SAT bits of `value`; the reserved bits are dropped.
    pub const fn from_u32(value: u32) -> Self {
        Self(value & (Self::NJ | Self::SAT))
    }

    /// Returns the register as the low word of `mfvscr` holds it.
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// Whether NJ is set: denormal elements are flushed to zero.
    pub const fn nj(self) -> bool {
        self.0 & Self::NJ != 0
    }

    /// Whether SAT is set.
    pub const fn sat(self) -> bool {
        self.0 & Self::SAT != 0
    }

    /// Sets SAT if `saturated`, leaving it set otherwise: the bit is sticky.
    #[inline]
    pub fn saturate_if(&mut self, saturated: bool) {
        if saturated {
            self.0 |= Self::SAT;
        }
    }

    /// `mfvscr`: the register in word 3 of a vector, words 0 to 2 zero.
    pub const fn mfvscr(self) -> V128 {
        V128([0, 0, 0, self.0])
    }

    /// `mtvscr`: takes NJ and SAT from word 3 of `vb`.
    pub fn mtvscr(&mut self, vb: V128) {
        *self = Self::from_u32(vb.0[3]);
    }
}

impl Default for Vscr {
    /// NJ set and SAT clear, as a thread starts.
    fn default() -> Self {
        Self(Self::NJ)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_register_is_in_non_java_mode() {
        let vscr = Vscr::default();
        assert!(vscr.nj());
        assert!(!vscr.sat());
        assert_eq!(vscr.to_u32(), 0x0001_0000);
    }

    #[test]
    fn sat_is_sticky_until_mtvscr() {
        let mut vscr = Vscr::default();
        vscr.saturate_if(false);
        assert!(!vscr.sat());
        vscr.saturate_if(true);
        vscr.saturate_if(false);
        assert!(vscr.sat());
        assert_eq!(vscr.mfvscr(), V128([0, 0, 0, 0x0001_0001]));
        vscr.mtvscr(V128([0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0x0001_0000]));
        assert!(!vscr.sat() && vscr.nj());
    }

    #[test]
    fn mtvscr_keeps_only_nj_and_sat_of_word_3() {
        let mut vscr = Vscr::default();
        vscr.mtvscr(V128([0, 0, 0, 0xFFFF_FFFF]));
        assert_eq!(vscr.to_u32(), Vscr::NJ | Vscr::SAT);
        vscr.mtvscr(V128([0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFE_FFFE]));
        assert_eq!(vscr.to_u32(), 0, "NJ cleared");
        assert_eq!(Vscr::from_u32(0x8000_0001).to_u32(), Vscr::SAT);
    }
}
