// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! AES-128-CBC decryption of the XEX payload.
//!
//! The security info holds a session key encrypted under a master key; the payload is encrypted
//! under the session key. Both use CBC with an all-zero IV. Keys and scheme follow
//! `src/xenia/cpu/xex_module.cc` in Xenia.

use aes::Aes128;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};

/// The master key of retail consoles.
pub const RETAIL_KEY: [u8; 16] = [
    0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3, 0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91,
];

/// The master key of development kits.
pub const DEVKIT_KEY: [u8; 16] = [0; 16];

/// AES block size in bytes.
const BLOCK_SIZE: usize = 16;

/// A master key the crate knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterKey {
    /// The key of retail consoles.
    Retail,
    /// The key of development kits.
    Devkit,
}

impl MasterKey {
    /// Every known key, in the order a loader tries them.
    pub const ALL: [MasterKey; 2] = [MasterKey::Retail, MasterKey::Devkit];

    /// Returns the key bytes.
    pub fn bytes(self) -> &'static [u8; 16] {
        match self {
            MasterKey::Retail => &RETAIL_KEY,
            MasterKey::Devkit => &DEVKIT_KEY,
        }
    }

    /// Recovers the session key from its encrypted form in the security info.
    pub fn session_key(self, encrypted: &[u8; 16]) -> [u8; 16] {
        let mut key = *encrypted;
        decrypt_cbc(self.bytes(), &mut key);
        key
    }
}

/// Decrypts `data` in place with AES-128-CBC and a zero IV.
///
/// Only whole blocks are decrypted. A shorter tail cannot be ciphertext produced by the format, so
/// it is left as it is, and whatever parses it next reports the problem.
pub fn decrypt_cbc(key: &[u8; 16], data: &mut [u8]) {
    let whole_blocks = data.len() - data.len() % BLOCK_SIZE;
    let decryptor = cbc::Decryptor::<Aes128>::new(key.into(), &[0; BLOCK_SIZE].into());
    // Removing "no padding" from a whole number of blocks has no failure case.
    let _ = decryptor.decrypt_padded::<NoPadding>(&mut data[..whole_blocks]);
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS-197 appendix C.1: AES-128 example vector.
    const FIPS_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    const FIPS_PLAIN: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    const FIPS_CIPHER: [u8; 16] = [
        0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5,
        0x5A,
    ];

    #[test]
    fn first_block_with_a_zero_iv_is_plain_aes() {
        let mut data = FIPS_CIPHER;
        decrypt_cbc(&FIPS_KEY, &mut data);
        assert_eq!(data, FIPS_PLAIN);
    }

    #[test]
    fn later_blocks_chain_with_the_previous_ciphertext() {
        let mut data = [FIPS_CIPHER, FIPS_CIPHER].concat();
        decrypt_cbc(&FIPS_KEY, &mut data);
        assert_eq!(data[..16], FIPS_PLAIN);
        for i in 0..16 {
            assert_eq!(data[16 + i], FIPS_PLAIN[i] ^ FIPS_CIPHER[i], "byte {i}");
        }
    }

    #[test]
    fn a_partial_tail_is_left_untouched() {
        let mut data = FIPS_CIPHER.to_vec();
        data.extend_from_slice(&[1, 2, 3]);
        decrypt_cbc(&FIPS_KEY, &mut data);
        assert_eq!(data[..16], FIPS_PLAIN);
        assert_eq!(data[16..], [1, 2, 3]);
    }

    #[test]
    fn input_shorter_than_a_block_is_left_untouched() {
        let mut data = [9, 9, 9];
        decrypt_cbc(&FIPS_KEY, &mut data);
        assert_eq!(data, [9, 9, 9]);
    }

    #[test]
    fn known_master_keys_match_the_values_loaders_use() {
        assert_eq!(MasterKey::Retail.bytes()[..4], [0x20, 0xB1, 0x85, 0xA5]);
        assert_eq!(MasterKey::Devkit.bytes(), &[0; 16]);
        assert_eq!(MasterKey::ALL, [MasterKey::Retail, MasterKey::Devkit]);
    }

    #[test]
    fn session_keys_decrypt_under_their_master_key() {
        let mut encrypted = *b"0123456789abcdef";
        crate::fixtures::encrypt_cbc(&RETAIL_KEY, &mut encrypted);
        assert_eq!(
            MasterKey::Retail.session_key(&encrypted),
            *b"0123456789abcdef"
        );
        assert_ne!(
            MasterKey::Devkit.session_key(&encrypted),
            *b"0123456789abcdef"
        );
    }
}
