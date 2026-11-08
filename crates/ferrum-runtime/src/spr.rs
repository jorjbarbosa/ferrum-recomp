// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The special-purpose registers that generated code may name.

/// A special-purpose register that `mfspr`, `mtspr` or `mftb` may name in generated code.
///
/// Any other number is a recompilation error: codegen asks [`Spr::for_mfspr`] or
/// [`Spr::for_mtspr`] and stops when they return `None`. TBL, TBU and PVR are read-only, because
/// time base writes use the privileged numbers 284 and 285, and PVR cannot be written at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Spr {
    /// The fixed-point exception register, number 1.
    Xer,
    /// The link register, number 8.
    Lr,
    /// The count register, number 9.
    Ctr,
    /// The vector save register, number 256.
    Vrsave,
    /// The time base, number 268. Reads all 64 bits, as on a 64-bit implementation.
    Tbl,
    /// The upper half of the time base, number 269.
    Tbu,
    /// The processor version register, number 287.
    Pvr,
}

impl Spr {
    /// Every register, in order of number.
    pub const ALL: [Self; 7] = [
        Self::Xer,
        Self::Lr,
        Self::Ctr,
        Self::Vrsave,
        Self::Tbl,
        Self::Tbu,
        Self::Pvr,
    ];

    /// Returns the register's number, as the instruction encodes it once its halves are swapped.
    pub const fn number(self) -> u32 {
        match self {
            Self::Xer => 1,
            Self::Lr => 8,
            Self::Ctr => 9,
            Self::Vrsave => 256,
            Self::Tbl => 268,
            Self::Tbu => 269,
            Self::Pvr => 287,
        }
    }

    /// Returns whether `mtspr` may write the register.
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::Xer | Self::Lr | Self::Ctr | Self::Vrsave)
    }

    /// Returns the register that `mfspr` (or `mftb`) reads for `number`, or `None` if generated
    /// code may not read it.
    pub const fn for_mfspr(number: u32) -> Option<Self> {
        match number {
            1 => Some(Self::Xer),
            8 => Some(Self::Lr),
            9 => Some(Self::Ctr),
            256 => Some(Self::Vrsave),
            268 => Some(Self::Tbl),
            269 => Some(Self::Tbu),
            287 => Some(Self::Pvr),
            _ => None,
        }
    }

    /// Returns the register that `mtspr` writes for `number`, or `None` if generated code may not
    /// write it.
    pub const fn for_mtspr(number: u32) -> Option<Self> {
        match Self::for_mfspr(number) {
            Some(spr) if spr.is_writable() => Some(spr),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_seven_registers_can_be_read() {
        let readable: Vec<_> = (0..1024).filter_map(Spr::for_mfspr).collect();
        assert_eq!(readable, Spr::ALL);
        for spr in Spr::ALL {
            assert_eq!(Spr::for_mfspr(spr.number()), Some(spr));
        }
    }

    #[test]
    fn only_xer_lr_ctr_and_vrsave_can_be_written() {
        let writable: Vec<_> = (0..1024).filter_map(Spr::for_mtspr).collect();
        assert_eq!(writable, [Spr::Xer, Spr::Lr, Spr::Ctr, Spr::Vrsave]);
        for number in [268, 269, 284, 285, 287] {
            assert_eq!(Spr::for_mtspr(number), None, "{number}");
        }
    }
}
