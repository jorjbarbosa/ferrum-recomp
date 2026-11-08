// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Turns the payload of a XEX file into the plain image: decryption, then decompression.
//!
//! Follows `XexModule::ReadImage` and its helpers in `src/xenia/cpu/xex_module.cc` in Xenia.

use std::borrow::Cow;

use sha1::{Digest, Sha1};

use crate::crypto::{MasterKey, decrypt_cbc};
use crate::error::{ErrorKind, Result};
use crate::header::{BasicBlock, Compression, Encryption, Header, SecurityInfo, security_field};
use crate::lzx::{self, FirstBlock};
use crate::reader::Reader;

/// The signature at the start of every PE image.
const PE_DOS_MAGIC: &[u8; 2] = b"MZ";

/// A decrypted and decompressed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPayload {
    /// The plain image, exactly as long as the security info says.
    pub image: Vec<u8>,
    /// The master key that decrypted the payload, or `None` if it was not encrypted.
    pub key: Option<MasterKey>,
}

/// Decrypts and decompresses the payload of `file`, whose headers were parsed into `header`.
pub fn decode(file: &[u8], header: &Header) -> Result<DecodedPayload> {
    let (plain, key) = decrypt(file, header)?;
    let image = decompress(&plain, header)?;
    Ok(DecodedPayload { image, key })
}

/// Returns the file with its payload decrypted, plus the key that did it.
///
/// The header region stays in place, so offsets into the result are also offsets into the file and
/// errors can name them directly.
fn decrypt<'a>(file: &'a [u8], header: &Header) -> Result<(Cow<'a, [u8]>, Option<MasterKey>)> {
    if header.file_format.encryption == Encryption::None {
        return Ok((Cow::Borrowed(file), None));
    }
    let start = payload_start(header);
    for key in MasterKey::ALL {
        let session_key = key.session_key(&header.security.encrypted_key);
        let mut plain = file.to_vec();
        if let Some(payload) = plain.get_mut(start..) {
            decrypt_cbc(&session_key, payload);
        }
        if is_plausible(&plain, header)? {
            return Ok((Cow::Owned(plain), Some(key)));
        }
    }
    let offset = u64::from(header.security_offset) + security_field::AES_KEY;
    Err(Reader::file(file).error(offset, "security_info.aes_key", ErrorKind::WrongKey))
}

/// Returns where the payload starts.
fn payload_start(header: &Header) -> usize {
    // A 32-bit offset fits in `usize` on every host this crate supports.
    header.header_size as usize
}

/// Tells a good decryption from a bad one: an LZX stream has a digest to match, and anything else
/// has to start with the signature of a PE image.
fn is_plausible(plain: &[u8], header: &Header) -> Result<bool> {
    if let Compression::Normal {
        first_block_size,
        first_block_digest,
        ..
    } = &header.file_format.compression
    {
        let first = FirstBlock {
            offset: header.header_size.into(),
            size: *first_block_size,
            digest: first_block_digest,
        };
        return lzx::first_block_matches(&Reader::file(plain), &first);
    }
    let payload = plain.get(payload_start(header)..).unwrap_or_default();
    Ok(payload.starts_with(PE_DOS_MAGIC))
}

/// Rebuilds the image from a decrypted file.
fn decompress(plain: &[u8], header: &Header) -> Result<Vec<u8>> {
    let reader = Reader::file(plain);
    let start = u64::from(header.header_size);
    let image_size = header.security.image_size;
    match &header.file_format.compression {
        Compression::None => Ok(reader.bytes(start, image_size.into(), "payload")?.to_vec()),
        Compression::Basic(blocks) => expand_basic(&reader, start, blocks, image_size),
        Compression::Normal {
            window_size,
            first_block_size,
            first_block_digest,
        } => {
            let first = FirstBlock {
                offset: start,
                size: *first_block_size,
                digest: first_block_digest,
            };
            let image = lzx::decompress(&reader, &first, *window_size, image_size)?;
            check_lzx_output(&reader, start, &image, &header.security)?;
            Ok(image)
        }
    }
}

/// Compares the output of the LZX decoder with the page digests.
///
/// The block digests only vouch for the compressed bytes, and the decoder accepts some invalid
/// streams, producing wrong output. A mismatch here is therefore fatal, unlike for the other
/// compression modes, where it can simply mean the image was modified after signing.
fn check_lzx_output(
    reader: &Reader<'_>,
    start: u64,
    image: &[u8],
    security: &SecurityInfo,
) -> Result<()> {
    let Some(run) = first_bad_page_run(image, security) else {
        return Ok(());
    };
    let kind = ErrorKind::CorruptLzx {
        reason: format!("the output does not match the digest of page run {run}"),
    };
    Err(reader.error(start, "lzx_stream", kind))
}

/// Expands a "basic" payload: runs of data from the file, each followed by a run of zeros.
///
/// Pages past the last block stay zero, as they do in Xenia, whose image starts out zeroed.
fn expand_basic(
    reader: &Reader<'_>,
    start: u64,
    blocks: &[BasicBlock],
    image_size: u32,
) -> Result<Vec<u8>> {
    let total = blocks.iter().fold(0u64, |total, block| {
        total + u64::from(block.data_size) + u64::from(block.zero_size)
    });
    if total > image_size.into() {
        let kind = ErrorKind::InvalidValue {
            value: total,
            reason: "the blocks expand to more than the image size",
        };
        return Err(reader.error(start, "file_format_info.basic_block", kind));
    }
    let mut image = Vec::with_capacity(image_size as usize);
    let mut cursor = start;
    for (index, block) in blocks.iter().enumerate() {
        let field = format!("basic_block[{index}].data");
        image.extend_from_slice(reader.bytes(cursor, block.data_size.into(), field)?);
        image.resize(image.len() + block.zero_size as usize, 0);
        cursor += u64::from(block.data_size);
    }
    image.resize(image_size as usize, 0);
    Ok(image)
}

/// Checks the image against the digest chain of the security info and returns the index of the
/// first run of pages that does not match, or `None` if all of them do.
///
/// The hash of each run covers its pages and its descriptor. The expected value of the first run
/// is in the security info, and each descriptor holds the expected value of the next run. Pages
/// that no descriptor covers count as a mismatch of the run after the last one, since otherwise
/// they would escape the check.
pub fn first_bad_page_run(image: &[u8], security: &SecurityInfo) -> Option<usize> {
    let page_size = u64::from(security.page_size());
    let reader = Reader::file(image);
    let mut expected = security.image_digest;
    let mut offset = 0u64;
    for (index, descriptor) in security.page_descriptors.iter().enumerate() {
        let size = u64::from(descriptor.page_count()) * page_size;
        let Ok(pages) = reader.bytes(offset, size, "page_run") else {
            return Some(index);
        };
        let mut hasher = Sha1::new();
        hasher.update(pages);
        hasher.update(descriptor.raw.to_be_bytes());
        hasher.update(descriptor.next_digest);
        if hasher.finalize().as_slice() != expected.as_slice() {
            return Some(index);
        }
        expected = descriptor.next_digest;
        offset += size;
    }
    (offset != image.len() as u64).then_some(security.page_descriptors.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Location;
    use crate::fixtures::lzx::{
        encode_uncompressed, encode_verbatim, repeated_offset_chunk, uncompressed_chunk,
    };
    use crate::fixtures::{BuiltXex, FixtureCompression, FixtureEncryption, XexBuilder, be32};
    use crate::fixtures::{PageRun, SESSION_KEY};
    use crate::header::key;

    /// An image with zero runs and repetition, spanning several LZX frames.
    fn image() -> Vec<u8> {
        let mut image = vec![0; 0x3_0000];
        image[..2].copy_from_slice(PE_DOS_MAGIC);
        for (i, byte) in image[0x100..0x9000].iter_mut().enumerate() {
            *byte = (i * 7 / 5) as u8;
        }
        for (i, byte) in image[0x1_2000..0x2_1000].iter_mut().enumerate() {
            *byte = b"pattern of repeating bytes "[i % 27];
        }
        image[0x2_FFFF] = 0x7F;
        image
    }

    fn build(compression: FixtureCompression, encryption: FixtureEncryption) -> BuiltXex {
        let mut builder = XexBuilder::new(image());
        builder.compression = compression;
        builder.encryption = encryption;
        builder.build()
    }

    fn build_plain(compression: FixtureCompression) -> BuiltXex {
        build(compression, FixtureEncryption::None)
    }

    fn decode_bytes(file: &[u8]) -> Result<DecodedPayload> {
        decode(file, &Header::parse(file)?)
    }

    fn format_info_offset(built: &BuiltXex) -> usize {
        built.optional_data_offset(key::FILE_FORMAT_INFO)
    }

    #[test]
    fn every_compression_round_trips_under_every_key() {
        let compressions = [
            FixtureCompression::None,
            FixtureCompression::Basic,
            FixtureCompression::LzxUncompressedBlocks,
            FixtureCompression::LzxVerbatimBlocks,
        ];
        let keys = [
            (FixtureEncryption::None, None),
            (FixtureEncryption::Retail, Some(MasterKey::Retail)),
            (FixtureEncryption::Devkit, Some(MasterKey::Devkit)),
        ];
        for compression in compressions {
            for (encryption, key) in keys {
                let built = build(compression.clone(), encryption);
                let decoded = decode_bytes(&built.bytes).unwrap();
                assert_eq!(decoded.key, key, "{compression:?} {encryption:?}");
                assert_eq!(decoded.image, image(), "{compression:?} {encryption:?}");
            }
        }
    }

    #[test]
    fn compressed_fixtures_really_are_smaller_than_the_image() {
        for compression in [
            FixtureCompression::Basic,
            FixtureCompression::LzxVerbatimBlocks,
        ] {
            let built = build_plain(compression.clone());
            let payload = built.bytes.len() - built.header_size as usize;
            assert!(payload < image().len(), "{compression:?}: {payload:#x}");
        }
    }

    #[test]
    fn encrypted_files_really_hide_the_image() {
        let built = build(FixtureCompression::None, FixtureEncryption::Retail);
        let payload = &built.bytes[built.header_size as usize..];
        assert_ne!(&payload[..2], PE_DOS_MAGIC);
        assert_ne!(payload, image());
        assert_ne!(
            Header::parse(&built.bytes).unwrap().security.encrypted_key,
            SESSION_KEY
        );
    }

    #[test]
    fn every_window_size_decodes() {
        for window_size in [0x8000, 0x1_0000, 0x2_0000, 0x10_0000, 0x20_0000] {
            let mut builder = XexBuilder::new(image());
            builder.compression = FixtureCompression::LzxVerbatimBlocks;
            builder.window_size = window_size;
            let decoded = decode_bytes(&builder.build().bytes).unwrap();
            assert_eq!(decoded.image, image(), "window {window_size:#x}");
        }
    }

    #[test]
    fn one_block_per_chunk_and_one_block_for_all_chunks_both_decode() {
        for chunks_per_block in [1, 100] {
            let mut builder = XexBuilder::new(image());
            builder.compression = FixtureCompression::LzxVerbatimBlocks;
            builder.chunks_per_block = chunks_per_block;
            let built = builder.build();
            assert_eq!(
                built.blocks.len(),
                if chunks_per_block == 1 { 6 } else { 1 }
            );
            assert_eq!(decode_bytes(&built.bytes).unwrap().image, image());
        }
    }

    #[test]
    fn an_image_shorter_than_a_frame_decodes() {
        let mut short = vec![0x11; 0x1000];
        short[..2].copy_from_slice(PE_DOS_MAGIC);
        for compression in [
            FixtureCompression::LzxUncompressedBlocks,
            FixtureCompression::LzxVerbatimBlocks,
        ] {
            let mut builder = XexBuilder::new(short.clone());
            builder.page_size = 0x1000;
            builder.compression = compression;
            assert_eq!(decode_bytes(&builder.build().bytes).unwrap().image, short);
        }
    }

    #[test]
    fn an_unknown_key_is_reported_at_the_key_field() {
        for compression in [
            FixtureCompression::None,
            FixtureCompression::Basic,
            FixtureCompression::LzxUncompressedBlocks,
            FixtureCompression::LzxVerbatimBlocks,
        ] {
            let built = build(compression.clone(), FixtureEncryption::UnknownKey);
            let err = decode_bytes(&built.bytes).unwrap_err();
            assert_eq!(err.kind, ErrorKind::WrongKey, "{compression:?}");
            assert_eq!(err.field, "security_info.aes_key");
            assert_eq!(
                err.location,
                Location::File(u64::from(built.security_offset) + 0x150)
            );
        }
    }

    #[test]
    fn a_truncated_plain_payload_is_reported_where_it_starts() {
        let built = build_plain(FixtureCompression::None);
        let file = &built.bytes[..built.bytes.len() - 1];
        let err = decode_bytes(file).unwrap_err();
        assert_eq!(err.field, "payload");
        assert_eq!(err.location, Location::File(built.header_size.into()));
        assert_eq!(
            err.kind,
            ErrorKind::Truncated {
                needed: 0x3_0000,
                available: 0x2_FFFF,
            }
        );
    }

    #[test]
    fn decoding_a_file_shorter_than_its_headers_is_an_error() {
        for encryption in [FixtureEncryption::None, FixtureEncryption::Retail] {
            let built = build(FixtureCompression::Basic, encryption);
            let header = Header::parse(&built.bytes).unwrap();
            assert!(
                decode(&built.bytes[..4], &header).is_err(),
                "{encryption:?}"
            );
        }
    }

    #[test]
    fn plaintext_longer_than_the_image_is_cut_to_the_image_size() {
        let mut file = build_plain(FixtureCompression::None).bytes;
        file.extend_from_slice(&[0xEE; 32]);
        assert_eq!(decode_bytes(&file).unwrap().image, image());
    }

    #[test]
    fn a_corrupt_first_block_without_encryption_is_a_digest_mismatch() {
        let built = build_plain(FixtureCompression::LzxVerbatimBlocks);
        let first = built.blocks[0];
        let mut file = built.bytes;
        file[first.offset + 30] ^= 1;
        let err = decode_bytes(&file).unwrap_err();
        assert_eq!(err.kind, ErrorKind::DigestMismatch);
        assert_eq!(err.field, "compressed_block[0]");
        assert_eq!(err.location, Location::File(first.offset as u64));
    }

    #[test]
    fn a_corrupt_later_block_names_the_block_and_its_offset() {
        let built = build_plain(FixtureCompression::LzxVerbatimBlocks);
        assert!(built.blocks.len() >= 2);
        let second = built.blocks[1];
        let mut file = built.bytes;
        file[second.offset + 40] ^= 0x80;
        let err = decode_bytes(&file).unwrap_err();
        assert_eq!(err.kind, ErrorKind::DigestMismatch);
        assert_eq!(err.field, "compressed_block[1]");
        assert_eq!(err.location, Location::File(second.offset as u64));
    }

    #[test]
    fn a_stream_with_a_bad_block_type_is_corrupt_lzx() {
        // One flag bit and a 3-bit block type of zero, under a correct digest chain.
        let built = build_plain(FixtureCompression::LzxChunks(vec![vec![0; 64]]));
        let err = decode_bytes(&built.bytes).unwrap_err();
        assert!(matches!(err.kind, ErrorKind::CorruptLzx { .. }), "{err}");
        assert_eq!(err.field, "compressed_block[0].chunk[0]");
        // The chunk data starts after the block header and the chunk's size prefix.
        let chunk = built.blocks[0].offset as u64 + 24 + 2;
        assert_eq!(err.location, Location::File(chunk));
    }

    #[test]
    fn a_chunk_cut_short_is_corrupt_lzx() {
        let mut chunks = encode_verbatim(&image(), 0x8000);
        let second = &mut chunks[1];
        second.truncate(second.len() / 2);
        let built = build_plain(FixtureCompression::LzxChunks(chunks));
        let err = decode_bytes(&built.bytes).unwrap_err();
        assert!(matches!(err.kind, ErrorKind::CorruptLzx { .. }), "{err}");
        assert_eq!(err.field, "compressed_block[0].chunk[1]");
    }

    #[test]
    fn a_stream_with_too_few_frames_is_truncated() {
        let mut chunks = encode_verbatim(&image(), 0x8000);
        chunks.truncate(2);
        let built = build_plain(FixtureCompression::LzxChunks(chunks));
        let err = decode_bytes(&built.bytes).unwrap_err();
        assert_eq!(err.field, "lzx_stream");
        assert_eq!(err.location, Location::File(built.header_size.into()));
        assert_eq!(
            err.kind,
            ErrorKind::Truncated {
                needed: 0x3_0000,
                available: 0x1_0000,
            }
        );
    }

    #[test]
    fn frames_past_the_end_of_the_image_are_ignored() {
        let mut longer = image();
        longer.extend_from_slice(&[0x55; 0x8000]);
        let chunks = encode_uncompressed(&longer);
        let built = build_plain(FixtureCompression::LzxChunks(chunks));
        assert_eq!(decode_bytes(&built.bytes).unwrap().image, image());
    }

    #[test]
    fn a_first_block_past_the_end_of_the_file_is_truncated() {
        for encryption in [FixtureEncryption::None, FixtureEncryption::Retail] {
            let built = build(FixtureCompression::LzxUncompressedBlocks, encryption);
            let mut file = built.bytes.clone();
            be32(&mut file, format_info_offset(&built) + 12, 0x7FFF_0000);
            let err = decode_bytes(&file).unwrap_err();
            assert_eq!(err.field, "compressed_block[0]");
            assert_eq!(err.location, Location::File(built.header_size.into()));
            assert!(matches!(err.kind, ErrorKind::Truncated { .. }));
        }
    }

    /// Makes a plaintext stream consist of this one block, repairing the digest that vouches for it.
    fn with_block(built: &BuiltXex, block: &[u8]) -> Vec<u8> {
        let mut file = built.bytes[..built.header_size as usize].to_vec();
        let info = format_info_offset(built);
        be32(&mut file, info + 12, block.len() as u32);
        let digest: [u8; 20] = Sha1::digest(block).into();
        file[info + 16..info + 36].copy_from_slice(&digest);
        file.extend_from_slice(block);
        file
    }

    #[test]
    fn a_block_too_small_for_its_header_is_invalid() {
        let built = build_plain(FixtureCompression::LzxUncompressedBlocks);
        let err = decode_bytes(&with_block(&built, &[0; 10])).unwrap_err();
        assert_eq!(err.field, "compressed_block[0]");
        assert_eq!(err.location, Location::File(built.header_size.into()));
        assert!(matches!(
            err.kind,
            ErrorKind::InvalidValue { value: 10, .. }
        ));
    }

    #[test]
    fn a_chunk_larger_than_its_block_is_truncated() {
        let built = build_plain(FixtureCompression::LzxUncompressedBlocks);
        let mut block = vec![0; 24];
        block.extend_from_slice(&0x100u16.to_be_bytes());
        block.extend_from_slice(&[0; 16]);
        let err = decode_bytes(&with_block(&built, &block)).unwrap_err();
        assert_eq!(err.field, "compressed_block[0].chunk[0]");
        assert_eq!(
            err.kind,
            ErrorKind::Truncated {
                needed: 0x100,
                available: 16,
            }
        );
    }

    #[test]
    fn a_block_without_a_closing_zero_size_is_invalid() {
        let built = build_plain(FixtureCompression::LzxUncompressedBlocks);
        let mut block = vec![0; 24];
        block.extend_from_slice(&4u16.to_be_bytes());
        block.extend_from_slice(&[0; 4]);
        let err = decode_bytes(&with_block(&built, &block)).unwrap_err();
        assert_eq!(err.field, "compressed_block[0].chunk[1]");
        assert!(matches!(err.kind, ErrorKind::InvalidValue { .. }));
    }

    #[test]
    fn a_next_block_past_the_end_of_the_file_is_truncated() {
        let built = build_plain(FixtureCompression::LzxUncompressedBlocks);
        let mut block = vec![0; 24];
        block[..4].copy_from_slice(&0x1000u32.to_be_bytes());
        block.extend_from_slice(&[0, 0]);
        let err = decode_bytes(&with_block(&built, &block)).unwrap_err();
        assert_eq!(err.field, "compressed_block[1]");
        assert!(matches!(err.kind, ErrorKind::Truncated { .. }));
    }

    #[test]
    fn a_stream_decoding_to_the_wrong_bytes_is_corrupt_lzx() {
        let mut expected = image();
        expected[0x2_0000] ^= 1;
        let chunks = encode_verbatim(&image(), 0x8000);
        let mut builder = XexBuilder::new(expected);
        builder.compression = FixtureCompression::LzxChunks(chunks);
        let built = builder.build();
        let err = decode_bytes(&built.bytes).unwrap_err();
        assert_eq!(err.field, "lzx_stream");
        assert_eq!(err.location, Location::File(built.header_size.into()));
        assert!(matches!(err.kind, ErrorKind::CorruptLzx { .. }), "{err}");
    }

    #[test]
    fn a_huge_repeated_offset_is_an_error_and_not_a_panic() {
        // An uncompressed block can load any value into R0, and a match can then use it. The
        // decoder neither rejects this nor copes with it, so the output cannot be right.
        for repeated_offset in [u32::MAX, 0x1000_0000, 0x8000_0000] {
            let chunks = vec![
                uncompressed_chunk(true, &[0x41; 0x8000], [repeated_offset, 1, 1]),
                repeated_offset_chunk(0x8000, 0x1000),
            ];
            let mut expected = vec![0x41; 0x8000];
            expected.extend_from_slice(&[0x42; 0x1000]);
            let mut builder = XexBuilder::new(expected);
            builder.page_size = 0x1000;
            builder.compression = FixtureCompression::LzxChunks(chunks);
            let err = decode_bytes(&builder.build().bytes).unwrap_err();
            assert_eq!(err.field, "lzx_stream", "R0 {repeated_offset:#x}: {err}");
            assert!(matches!(err.kind, ErrorKind::CorruptLzx { .. }), "{err}");
        }
    }

    #[test]
    fn basic_blocks_past_the_end_of_the_file_are_truncated() {
        let built = build_plain(FixtureCompression::Basic);
        let file = &built.bytes[..built.bytes.len() - 8];
        let err = decode_bytes(file).unwrap_err();
        assert!(err.field.starts_with("basic_block["), "{err}");
        assert!(err.field.ends_with("].data"), "{err}");
        assert!(matches!(err.kind, ErrorKind::Truncated { .. }));
    }

    #[test]
    fn basic_blocks_larger_than_the_image_are_invalid() {
        let built = build_plain(FixtureCompression::Basic);
        let mut file = built.bytes.clone();
        be32(&mut file, format_info_offset(&built) + 12, u32::MAX);
        let err = decode_bytes(&file).unwrap_err();
        assert_eq!(err.field, "file_format_info.basic_block");
        assert_eq!(err.location, Location::File(built.header_size.into()));
    }

    #[test]
    fn basic_images_end_in_zeros_when_the_blocks_stop_early() {
        let mut data = image();
        data[0x2_FFFF] = 0;
        data[0x2_0000..].fill(0);
        let mut builder = XexBuilder::new(data.clone());
        builder.compression = FixtureCompression::Basic;
        let built = builder.build();
        let mut file = built.bytes.clone();
        // Shrink the last zero run. The image keeps its size, the rest being implied zeros.
        let info = format_info_offset(&built);
        let size = u32::from_be_bytes(file[info..info + 4].try_into().unwrap()) as usize;
        be32(&mut file, info + size - 4, 0);
        assert_eq!(decode_bytes(&file).unwrap().image, data);
    }

    fn security_with_runs() -> SecurityInfo {
        let mut builder = XexBuilder::new(image());
        builder.page_runs = Some(vec![
            PageRun { kind: 3, pages: 1 },
            PageRun { kind: 1, pages: 1 },
            PageRun { kind: 2, pages: 1 },
        ]);
        Header::parse(&builder.build().bytes).unwrap().security
    }

    #[test]
    fn the_page_digest_chain_accepts_a_good_image() {
        assert_eq!(first_bad_page_run(&image(), &security_with_runs()), None);
    }

    #[test]
    fn the_page_digest_chain_names_the_first_bad_run() {
        let security = security_with_runs();
        for (offset, run) in [(0x10, 0), (0x1_0010, 1), (0x2_0010, 2)] {
            let mut bad = image();
            bad[offset] ^= 1;
            assert_eq!(first_bad_page_run(&bad, &security), Some(run));
        }
    }

    #[test]
    fn the_page_digest_chain_rejects_an_image_longer_than_its_pages() {
        let mut long = image();
        long.push(0);
        assert_eq!(first_bad_page_run(&long, &security_with_runs()), Some(3));
    }

    #[test]
    fn the_page_digest_chain_rejects_an_image_shorter_than_its_pages() {
        let short = &image()[..0x8000];
        assert_eq!(first_bad_page_run(short, &security_with_runs()), Some(0));
    }
}
