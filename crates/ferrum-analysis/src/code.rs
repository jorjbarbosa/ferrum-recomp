// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! A stretch of guest code in memory order.

/// The bytes of a stretch of guest code, in big-endian order, and the address of the first one.
#[derive(Debug, Clone, Copy)]
pub struct Code<'a> {
    base: u32,
    bytes: &'a [u8],
}

impl<'a> Code<'a> {
    /// Wraps `bytes`, the first of which is at guest address `base`.
    pub fn new(base: u32, bytes: &'a [u8]) -> Self {
        Self { base, bytes }
    }

    /// The address of the first byte.
    pub fn base(&self) -> u32 {
        self.base
    }

    /// One past the address of the last byte. It can be 2^32, hence `u64`.
    pub fn end(&self) -> u64 {
        u64::from(self.base) + self.bytes.len() as u64
    }

    /// Returns the word at `addr`, if `addr` is a multiple of 4 from the base and all four bytes are
    /// inside.
    pub fn word(&self, addr: u32) -> Option<u32> {
        let offset = addr.checked_sub(self.base)? as usize;
        if !offset.is_multiple_of(4) {
            return None;
        }
        let bytes = self.bytes.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    /// Returns the `len` bytes from `addr`, if all of them are inside.
    pub fn bytes(&self, addr: u32, len: usize) -> Option<&'a [u8]> {
        let offset = addr.checked_sub(self.base)? as usize;
        self.bytes.get(offset..offset.checked_add(len)?)
    }

    /// Every whole word, with its address, in address order.
    pub fn words(&self) -> impl Iterator<Item = (u32, u32)> + 'a {
        let base = self.base;
        let (words, _) = self.bytes.as_chunks::<4>();
        words.iter().enumerate().map(move |(index, bytes)| {
            // A slice of 4 GiB at most, so the offset fits in 32 bits; the sum wraps like guest
            // addresses do.
            let addr = base.wrapping_add((index * 4) as u32);
            (addr, u32::from_be_bytes(*bytes))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_big_endian_and_aligned_from_the_base() {
        let bytes = [0x38, 0x60, 0x00, 0x01, 0x4E, 0x80, 0x00, 0x20, 0xAA];
        let code = Code::new(0x8000_0000, &bytes);
        assert_eq!(code.word(0x8000_0000), Some(0x3860_0001));
        assert_eq!(code.word(0x8000_0004), Some(0x4E80_0020));
        assert_eq!(code.word(0x8000_0002), None);
        assert_eq!(code.word(0x8000_0008), None, "only one byte is left");
        assert_eq!(code.word(0x7FFF_FFFC), None);
        assert_eq!(code.end(), 0x8000_0009);
        assert_eq!(code.bytes(0x8000_0007, 2), Some(&[0x20, 0xAA][..]));
        assert_eq!(code.bytes(0x8000_0008, 2), None);
        assert_eq!(code.bytes(0x7FFF_FFFF, 1), None);
        let words: Vec<(u32, u32)> = code.words().collect();
        assert_eq!(
            words,
            [(0x8000_0000, 0x3860_0001), (0x8000_0004, 0x4E80_0020)]
        );
    }
}
