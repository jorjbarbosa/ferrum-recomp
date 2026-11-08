// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Helpers that generated code calls for operations the ISA defines in more than one step.
//!
//! Generated code runs in 32-bit mode, so the carry and overflow here come from the low 32 bits,
//! while results keep all 64. The floating-point instructions are below too, with the NaN rule of
//! the ISA, and the vector instructions of VMX and VMX128.

mod float;
pub(crate) mod vector;

pub(crate) use float::is_snan;
pub use float::{
    DEFAULT_NAN, double_to_single, fabs, fadd, fadds, fcfid, fctid, fctidz, fctiw, fctiwz, fdiv,
    fdivs, fmadd, fmadds, fmsub, fmsubs, fmul, fmuls, fnabs, fneg, fnmadd, fnmadds, fnmsub,
    fnmsubs, fres, frsp, frsqrte, fsel, fsqrt, fsqrts, fsub, fsubs, single_to_double,
};
pub use vector::*;

/// The ISA's ROTL32: rotates the low word of `value` left by `n` (modulo 32), with the rotated word
/// in both halves of the result, as `rlwinm`, `rlwnm` and `rlwimi` see it before masking.
#[inline]
pub fn rotl32(value: u64, n: u32) -> u64 {
    // Truncation to the low word is the definition.
    let word = (value as u32).rotate_left(n);
    (u64::from(word) << 32) | u64::from(word)
}

/// Adds `a`, `b` and `carry` as the XO-form additions do in 32-bit mode, and returns the 64-bit
/// result, CA (the carry out of the low word) and OV (the signed overflow of the low word).
///
/// Every add and subtract that sets CA is one call: `subfc` is `add_with_carry(!a, b, true)`,
/// `addme` is `add_with_carry(a, u64::MAX, ca)`, and so on.
#[inline]
pub fn add_with_carry(a: u64, b: u64, carry: bool) -> (u64, bool, bool) {
    let carry = u64::from(carry);
    let result = a.wrapping_add(b).wrapping_add(carry);
    // Truncations to the low words are intended: CA and OV come from them in 32-bit mode.
    let low = u64::from(a as u32) + u64::from(b as u32) + carry;
    let signed = i64::from(a as i32) + i64::from(b as i32) + carry as i64;
    let ca = low >> 32 != 0;
    let ov = signed != i64::from(signed as i32);
    (result, ca, ov)
}

/// Panics for a trap instruction at `addr` whose condition holds. Interrupts are not supported.
#[cold]
#[inline(never)]
pub fn trap(addr: u32) -> ! {
    panic!("trap at {addr:#010x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotl32_puts_the_rotated_word_in_both_halves() {
        assert_eq!(rotl32(0xFFFF_FFFF_8000_0001, 1), 0x0000_0003_0000_0003);
        assert_eq!(rotl32(0x1234_5678, 0), 0x1234_5678_1234_5678);
        assert_eq!(rotl32(0x1234_5678, 8), 0x3456_7812_3456_7812);
        assert_eq!(rotl32(0x1234_5678, 32), 0x1234_5678_1234_5678);
    }

    #[test]
    fn add_with_carry_takes_ca_and_ov_from_the_low_word() {
        // The case of seq_branch_carry: no carry out of the low word, though 64 bits would carry.
        let (sum, ca, ov) = add_with_carry(0xFFFF_FFFF_0000_0000, u64::MAX, false);
        assert_eq!((sum, ca, ov), (0xFFFF_FFFE_FFFF_FFFF, false, false));
        assert_eq!(
            add_with_carry(0xFFFF_FFFF, 1, false),
            (0x1_0000_0000, true, false)
        );
        assert_eq!(
            add_with_carry(0xFFFF_FFFF, 0, true),
            (0x1_0000_0000, true, false)
        );
        assert_eq!(
            add_with_carry(0x7FFF_FFFF, 1, false),
            (0x8000_0000, false, true)
        );
        assert_eq!(
            add_with_carry(0x8000_0000, 0x8000_0000, false),
            (0x1_0000_0000, true, true)
        );
        // subfc of equal values: !a + a + 1 carries, as a subtraction without borrow does.
        assert_eq!(add_with_carry(!5, 5, true), (0, true, false));
        assert_eq!(add_with_carry(!6, 5, true), (u64::MAX, false, false));
    }

    #[test]
    #[should_panic(expected = "trap at 0x82001234")]
    fn trap_panics_with_the_address() {
        trap(0x8200_1234);
    }
}
