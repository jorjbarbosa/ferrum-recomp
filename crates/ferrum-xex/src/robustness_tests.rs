// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Corrupt input, generated in bulk: whatever a file holds, parsing must end in a value or in an
//! error that says where and what, and never in a panic.

use sha1::{Digest, Sha1};

use crate::Xex;
use crate::error::{Error, ErrorKind, Location};
use crate::fixtures::lzx::{encode_uncompressed, encode_verbatim, uncompressed_chunk};
use crate::fixtures::sample::SampleLayout;
use crate::fixtures::{BuiltXex, FixtureCompression, FixtureEncryption, XexBuilder, be32};
use crate::header::key;

/// A small deterministic random number generator, so that failures can be reproduced.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit.max(1) as u64) as usize
    }
}

/// Fails unless the error names a field and renders both its location and that field.
fn assert_is_located(error: &Error) {
    assert!(!error.field.is_empty(), "{error:?}");
    let message = error.to_string();
    assert!(message.contains(error.field.as_ref()), "{message}");
    let offset = match error.location {
        Location::File(offset) => format!("file offset {offset:#x}"),
        Location::Image(offset) => format!("image offset {offset:#x}"),
    };
    assert!(message.contains(&offset), "{message}");
}

/// Parses, checking that a failure is reported properly. A panic fails the test by itself.
fn parse_checked(bytes: &[u8]) {
    if let Err(error) = Xex::parse(bytes) {
        assert_is_located(&error);
    }
}

fn tiny() -> XexBuilder {
    SampleLayout::tiny().builder()
}

fn tiny_with(compression: FixtureCompression, encryption: FixtureEncryption) -> BuiltXex {
    let mut builder = tiny();
    builder.compression = compression;
    builder.encryption = encryption;
    builder.build()
}

/// The ways of building the tiny module that a bulk test should go through.
fn all_formats() -> Vec<BuiltXex> {
    let mut built = Vec::new();
    for compression in [
        FixtureCompression::None,
        FixtureCompression::Basic,
        FixtureCompression::LzxVerbatimBlocks,
    ] {
        for encryption in [FixtureEncryption::None, FixtureEncryption::Retail] {
            built.push(tiny_with(compression.clone(), encryption));
        }
    }
    built
}

#[test]
fn the_tiny_module_is_valid_in_every_format() {
    for built in all_formats() {
        let xex = Xex::parse(&built.bytes).unwrap();
        assert_eq!(xex.warnings, []);
        assert_eq!(xex.image.base, 0x9200_0000);
        assert_eq!(xex.image.pdata.len(), 3);
        assert_eq!(xex.image.imports.len(), 2);
    }
}

#[test]
fn every_truncation_of_the_headers_is_a_located_error() {
    for built in all_formats() {
        for length in 0..built.header_size as usize {
            let error = Xex::parse(&built.bytes[..length]).unwrap_err();
            assert_is_located(&error);
        }
    }
}

#[test]
fn every_truncation_of_a_plain_payload_is_a_located_error() {
    let built = tiny_with(FixtureCompression::None, FixtureEncryption::None);
    let start = built.header_size as usize;
    for length in (start..built.bytes.len()).step_by(61) {
        let error = Xex::parse(&built.bytes[..length]).unwrap_err();
        assert_eq!(error.field, "payload");
        assert_eq!(error.location, Location::File(start as u64));
    }
}

#[test]
fn every_truncation_of_a_compressed_payload_is_handled() {
    for compression in [
        FixtureCompression::Basic,
        FixtureCompression::LzxVerbatimBlocks,
    ] {
        for encryption in [FixtureEncryption::None, FixtureEncryption::Retail] {
            let built = tiny_with(compression.clone(), encryption);
            let start = built.header_size as usize;
            for length in (start..built.bytes.len()).step_by(61) {
                parse_checked(&built.bytes[..length]);
            }
        }
    }
}

#[test]
fn no_change_to_a_header_byte_causes_a_panic() {
    for built in all_formats() {
        for offset in 0..built.header_size as usize {
            for value in [0x00, 0xFF, built.bytes[offset] ^ 0x80] {
                let mut file = built.bytes.clone();
                file[offset] = value;
                parse_checked(&file);
            }
        }
    }
}

#[test]
fn no_change_to_an_image_byte_causes_a_panic() {
    // A plain payload is the image, so this reaches the PE headers and the tables they point to.
    let built = tiny_with(FixtureCompression::None, FixtureEncryption::None);
    let start = built.header_size as usize;
    let regions = [0..0x400, 0x400..0x480, 0xA00..0xA20, 0x2100..0x2120];
    for offset in regions.into_iter().flatten() {
        let mut file = built.bytes.clone();
        for value in [0x00, 0xFF, file[start + offset] ^ 0x80] {
            file[start + offset] = value;
            parse_checked(&file);
        }
    }
}

#[test]
fn random_header_damage_never_panics() {
    let mut random = XorShift(0x9E37_79B9_7F4A_7C15);
    for built in all_formats() {
        for _ in 0..300 {
            let mut file = built.bytes.clone();
            for _ in 0..1 + random.below(16) {
                let offset = random.below(built.header_size as usize);
                file[offset] = random.next() as u8;
            }
            parse_checked(&file);
        }
    }
}

/// Damages LZX chunks: flips bits, overwrites bytes or cuts the chunk short.
fn damage_chunks(chunks: &mut [Vec<u8>], random: &mut XorShift) {
    for _ in 0..1 + random.below(8) {
        let index = random.below(chunks.len());
        let chunk = &mut chunks[index];
        if chunk.is_empty() {
            continue;
        }
        // Half of the time aim at the start, where the trees are.
        let limit = if random.next() & 1 == 0 {
            chunk.len().min(0x100)
        } else {
            chunk.len()
        };
        let offset = random.below(limit);
        match random.below(3) {
            0 => chunk[offset] ^= 1 << random.below(8),
            1 => chunk[offset] = random.next() as u8,
            _ => chunk.truncate(offset),
        }
    }
}

#[test]
fn damaged_lzx_streams_under_valid_digests_never_panic() {
    let layout = SampleLayout::tiny();
    let image = layout.builder().image;
    let verbatim = encode_verbatim(&image, 0x8000);
    let uncompressed = encode_uncompressed(&image);
    let mut random = XorShift(0xD1B5_4A32_D192_ED03);
    for round in 0..600 {
        let mut chunks = if round % 2 == 0 {
            verbatim.clone()
        } else {
            uncompressed.clone()
        };
        damage_chunks(&mut chunks, &mut random);
        let mut builder = layout.builder();
        builder.compression = FixtureCompression::LzxChunks(chunks);
        parse_checked(&builder.build().bytes);
    }
}

#[test]
fn random_bytes_as_lzx_streams_never_panic() {
    let layout = SampleLayout::tiny();
    let mut random = XorShift(0xA076_1D64_78BD_642F);
    for _ in 0..300 {
        let chunks = (0..1 + random.below(3))
            .map(|_| {
                let length = 1 + random.below(0x400);
                (0..length).map(|_| random.next() as u8).collect()
            })
            .collect();
        let mut builder = layout.builder();
        builder.compression = FixtureCompression::LzxChunks(chunks);
        let error = Xex::parse(&builder.build().bytes).unwrap_err();
        assert_is_located(&error);
    }
}

#[test]
fn uncompressed_blocks_can_load_any_repeated_offset() {
    let image = SampleLayout::tiny().builder().image;
    // The frame carries the right bytes, so bad repeated offsets alone do no harm until used.
    let chunks = vec![uncompressed_chunk(true, &image, [u32::MAX, 0, 0x8000_0000])];
    let mut builder = SampleLayout::tiny().builder();
    builder.compression = FixtureCompression::LzxChunks(chunks);
    assert_eq!(
        Xex::parse(&builder.build().bytes).unwrap().image.data,
        image
    );
}

/// Corrupts a file and states what the error must say.
struct Case {
    name: &'static str,
    built: BuiltXex,
    corrupt: fn(&mut Vec<u8>, &BuiltXex),
    field: &'static str,
    location: fn(&BuiltXex) -> Location,
}

fn plain() -> BuiltXex {
    tiny_with(FixtureCompression::None, FixtureEncryption::None)
}

fn lzx() -> BuiltXex {
    tiny_with(
        FixtureCompression::LzxVerbatimBlocks,
        FixtureEncryption::None,
    )
}

/// Puts `blocks` in place of the whole LZX stream, with digests that vouch for it.
fn replace_stream(file: &mut Vec<u8>, built: &BuiltXex, block: &[u8]) {
    file.truncate(built.header_size as usize);
    let info = built.optional_data_offset(key::FILE_FORMAT_INFO);
    be32(file, info + 12, block.len() as u32);
    let digest: [u8; 20] = Sha1::digest(block).into();
    file[info + 16..info + 36].copy_from_slice(&digest);
    file.extend_from_slice(block);
}

/// The failures the parser reports with their location, one of each kind.
fn located_failures() -> Vec<Case> {
    vec![
        Case {
            name: "invalid XEX: bad magic",
            built: plain(),
            corrupt: |file, _| file[0] = 0,
            field: "header.magic",
            location: |_| Location::File(0),
        },
        Case {
            name: "invalid XEX: truncated security info",
            built: plain(),
            corrupt: |file, built| {
                let at = built.security_offset as usize;
                file.truncate(at);
                be32(file, 8, at as u32);
            },
            field: "security_info",
            location: |built| Location::File(built.security_offset.into()),
        },
        Case {
            name: "invalid XEX: missing file format info",
            built: plain(),
            corrupt: |file, built| {
                let at = built.optional_entry_offset(key::FILE_FORMAT_INFO);
                be32(file, at, 0);
            },
            field: "optional.file_format_info",
            location: |_| Location::File(0x14),
        },
        Case {
            name: "invalid XEX: image without a PE signature",
            built: plain(),
            corrupt: |file, built| file[built.header_size as usize] = 0,
            field: "pe.dos.magic",
            location: |_| Location::Image(0),
        },
        Case {
            name: "wrong key",
            built: tiny_with(FixtureCompression::None, FixtureEncryption::UnknownKey),
            corrupt: |_, _| {},
            field: "security_info.aes_key",
            location: |built| Location::File(u64::from(built.security_offset) + 0x150),
        },
        Case {
            name: "wrong key over LZX",
            built: tiny_with(
                FixtureCompression::LzxVerbatimBlocks,
                FixtureEncryption::UnknownKey,
            ),
            corrupt: |_, _| {},
            field: "security_info.aes_key",
            location: |built| Location::File(u64::from(built.security_offset) + 0x150),
        },
        Case {
            name: "corrupt LZX: digest of a block",
            built: lzx(),
            corrupt: |file, built| file[built.blocks[0].offset + 26] ^= 1,
            field: "compressed_block[0]",
            location: |built| Location::File(built.blocks[0].offset as u64),
        },
        Case {
            name: "corrupt LZX: chunk larger than its block",
            built: lzx(),
            corrupt: |file, built| {
                let mut block = vec![0; 24];
                block.extend_from_slice(&0xFFFFu16.to_be_bytes());
                replace_stream(file, built, &block);
            },
            field: "compressed_block[0].chunk[0]",
            location: |built| Location::File(u64::from(built.header_size) + 26),
        },
        Case {
            name: "corrupt LZX: undecodable stream",
            built: tiny_with(
                FixtureCompression::LzxChunks(vec![vec![0; 64]]),
                FixtureEncryption::None,
            ),
            corrupt: |_, _| {},
            field: "compressed_block[0].chunk[0]",
            location: |built| Location::File(built.blocks[0].offset as u64 + 26),
        },
        Case {
            name: "corrupt LZX: wrong output",
            built: {
                let mut builder = tiny();
                let chunks = encode_verbatim(&builder.image, 0x8000);
                builder.image[0x3000] ^= 1;
                builder.compression = FixtureCompression::LzxChunks(chunks);
                builder.build()
            },
            corrupt: |_, _| {},
            field: "lzx_stream",
            location: |built| Location::File(built.header_size.into()),
        },
    ]
}

#[test]
fn every_promised_failure_names_its_offset_and_field() {
    for case in located_failures() {
        let mut file = case.built.bytes.clone();
        (case.corrupt)(&mut file, &case.built);
        let error = Xex::parse(&file).expect_err(case.name);
        assert_is_located(&error);
        assert_eq!(error.field, case.field, "{}: {error}", case.name);
        assert_eq!(
            error.location,
            (case.location)(&case.built),
            "{}: {error}",
            case.name
        );
    }
}

#[test]
fn a_corrupt_encrypted_start_is_reported_as_a_key_problem() {
    // Without a digest to check, a bad first block and a wrong key look the same.
    let built = tiny_with(FixtureCompression::None, FixtureEncryption::Retail);
    let mut file = built.bytes.clone();
    file[built.header_size as usize] ^= 1;
    let error = Xex::parse(&file).unwrap_err();
    assert_eq!(error.kind, ErrorKind::WrongKey);
}

#[test]
fn corruption_past_the_start_of_an_encrypted_payload_is_caught_by_the_page_digests() {
    for compression in [FixtureCompression::None, FixtureCompression::Basic] {
        let built = tiny_with(compression, FixtureEncryption::Retail);
        let mut file = built.bytes.clone();
        file[built.header_size as usize + 0x20] ^= 1;
        match Xex::parse(&file) {
            // CBC garbles the block, which may also break a PE field: both outcomes name it.
            Err(error) => assert_is_located(&error),
            Ok(xex) => assert!(!xex.warnings.is_empty()),
        }
    }
}
