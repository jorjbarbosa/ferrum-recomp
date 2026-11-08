// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The "normal" XEX compression: an LZX stream wrapped in hash-chained blocks.
//!
//! Each block starts with the size and SHA-1 of the next block, then holds chunks of compressed
//! data with a 16-bit size prefix, ended by a zero size. Follows `XexModule::ReadImageCompressed`
//! in `src/xenia/cpu/xex_module.cc` in Xenia. Decoding the chunks is left to the `lzxd` crate.

use lzxd::{Lzxd, MAX_CHUNK_SIZE, WindowSize};
use sha1::{Digest, Sha1};

use crate::error::{ErrorKind, Result};
use crate::reader::Reader;

/// Size of the next-block size and digest at the start of each block.
const BLOCK_HEADER_SIZE: u64 = 24;

/// The location and contents of one chunk of compressed data.
struct Chunk<'a> {
    /// File offset of the chunk's data.
    offset: u64,
    /// Index of the block the chunk belongs to.
    block: usize,
    /// Index of the chunk within its block.
    index: usize,
    /// The compressed bytes.
    data: &'a [u8],
}

/// The first block of a stream, as described by the file format info.
pub(crate) struct FirstBlock<'a> {
    /// File offset of the block.
    pub(crate) offset: u64,
    /// Size of the block.
    pub(crate) size: u32,
    /// SHA-1 of the block.
    pub(crate) digest: &'a [u8; 20],
}

/// Returns the SHA-1 of the first block of a stream, to tell a good decryption from a bad one.
pub(crate) fn first_block_matches(reader: &Reader<'_>, first: &FirstBlock<'_>) -> Result<bool> {
    let block = reader.bytes(first.offset, first.size.into(), "compressed_block[0]")?;
    Ok(Sha1::digest(block).as_slice() == first.digest.as_slice())
}

/// Decompresses a stream of hash-chained blocks into exactly `image_size` bytes.
pub(crate) fn decompress(
    reader: &Reader<'_>,
    first: &FirstBlock<'_>,
    window_size: u32,
    image_size: u32,
) -> Result<Vec<u8>> {
    let chunks = read_chunks(reader, first)?;
    decode_chunks(reader, &chunks, first.offset, window_size, image_size)
}

/// Walks the block chain, checking each digest, and collects the chunks.
fn read_chunks<'a>(reader: &Reader<'a>, first: &FirstBlock<'_>) -> Result<Vec<Chunk<'a>>> {
    let mut chunks = Vec::new();
    let mut offset = first.offset;
    let mut size = first.size;
    let mut digest = *first.digest;
    let mut block = 0;
    while size != 0 {
        let field = || format!("compressed_block[{block}]");
        let bytes = reader.bytes(offset, size.into(), field())?;
        if Sha1::digest(bytes).as_slice() != digest.as_slice() {
            return Err(reader.error(offset, field(), ErrorKind::DigestMismatch));
        }
        if u64::from(size) < BLOCK_HEADER_SIZE {
            let kind = ErrorKind::InvalidValue {
                value: size.into(),
                reason: "a compressed block must hold the size and digest of the next one",
            };
            return Err(reader.error(offset, field(), kind));
        }
        let next_size = reader.be_u32(offset, format!("{}.next_size", field()))?;
        digest = reader.array(offset + 4, format!("{}.next_digest", field()))?;
        read_block_chunks(reader, offset, size, block, &mut chunks)?;
        offset += u64::from(size);
        size = next_size;
        block += 1;
    }
    Ok(chunks)
}

/// Collects the chunks of the block of `size` bytes at `offset`.
fn read_block_chunks<'a>(
    reader: &Reader<'a>,
    offset: u64,
    size: u32,
    block: usize,
    chunks: &mut Vec<Chunk<'a>>,
) -> Result<()> {
    // Reads below stop at the end of this block, even when the file goes on.
    let end = offset + u64::from(size);
    let mut cursor = offset + BLOCK_HEADER_SIZE;
    let mut index = 0;
    loop {
        let field = || format!("compressed_block[{block}].chunk[{index}]");
        if cursor + 2 > end {
            let kind = ErrorKind::InvalidValue {
                value: size.into(),
                reason: "the block ends before the zero size that closes its chunks",
            };
            return Err(reader.error(cursor, field(), kind));
        }
        let chunk_size = u64::from(reader.be_u16(cursor, field())?);
        cursor += 2;
        if chunk_size == 0 {
            return Ok(());
        }
        if cursor + chunk_size > end {
            let kind = ErrorKind::Truncated {
                needed: chunk_size,
                available: end - cursor,
            };
            return Err(reader.error(cursor, field(), kind));
        }
        chunks.push(Chunk {
            offset: cursor,
            block,
            index,
            data: reader.bytes(cursor, chunk_size, field())?,
        });
        cursor += chunk_size;
        index += 1;
    }
}

/// Runs the LZX decoder over the chunks. Each chunk is one frame of 32 KiB of output, except that
/// the last frame stops at the end of the image.
fn decode_chunks(
    reader: &Reader<'_>,
    chunks: &[Chunk<'_>],
    stream_offset: u64,
    window_size: u32,
    image_size: u32,
) -> Result<Vec<u8>> {
    let image_size = image_size as usize;
    let mut decoder = Lzxd::new(window_size_of(window_size));
    let mut image = Vec::with_capacity(image_size);
    for chunk in chunks {
        let frame = MAX_CHUNK_SIZE.min(image_size - image.len());
        if frame == 0 {
            break;
        }
        let output = decoder.decompress_next(chunk.data, frame).map_err(|err| {
            reader.error(
                chunk.offset,
                format!("compressed_block[{}].chunk[{}]", chunk.block, chunk.index),
                ErrorKind::CorruptLzx {
                    reason: err.to_string(),
                },
            )
        })?;
        image.extend_from_slice(output);
    }
    if image.len() == image_size {
        return Ok(image);
    }
    let kind = ErrorKind::Truncated {
        needed: image_size as u64,
        available: image.len() as u64,
    };
    Err(reader.error(stream_offset, "lzx_stream", kind))
}

/// Maps a window size in bytes, which [`crate::Header::parse`] validated, to the decoder's type.
fn window_size_of(bytes: u32) -> WindowSize {
    match bytes {
        0x1_0000 => WindowSize::KB64,
        0x2_0000 => WindowSize::KB128,
        0x4_0000 => WindowSize::KB256,
        0x8_0000 => WindowSize::KB512,
        0x10_0000 => WindowSize::MB1,
        0x20_0000 => WindowSize::MB2,
        0x40_0000 => WindowSize::MB4,
        0x80_0000 => WindowSize::MB8,
        0x100_0000 => WindowSize::MB16,
        0x200_0000 => WindowSize::MB32,
        // The header check leaves only 32 KiB here.
        _ => WindowSize::KB32,
    }
}
