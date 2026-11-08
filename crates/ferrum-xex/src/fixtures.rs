// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Synthetic XEX2 files for tests.
//!
//! Everything here is generated from scratch; no byte comes from a real game. The module is only
//! compiled for this crate's tests and, through the `fixtures` feature, for the tests of other
//! crates.

pub mod lzx;
pub mod sample;

use aes::Aes128;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeEncrypt, KeyIvInit};
use sha1::{Digest, Sha1};

use crate::crypto::{DEVKIT_KEY, RETAIL_KEY};
use crate::header::{ImageFlags, XEX2_MAGIC, key};

/// The session key of every encrypted fixture.
pub const SESSION_KEY: [u8; 16] = *b"synthetic-sesskw";

/// Writes a big-endian `u32` over the four bytes at `offset`.
///
/// # Panics
///
/// Panics if the bytes are out of bounds, which is a bug in the test using it.
pub fn be32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

/// Rounds `value` up to a multiple of `align`, which must be a power of two.
fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Encrypts whole blocks with AES-128-CBC and a zero IV, the inverse of what a XEX loader does.
///
/// # Panics
///
/// Panics if the length is not a multiple of 16, which is a bug in the fixture.
pub fn encrypt_cbc(key: &[u8; 16], data: &mut [u8]) {
    let len = data.len();
    cbc::Encryptor::<Aes128>::new(key.into(), &[0; 16].into())
        .encrypt_padded::<NoPadding>(data, len)
        .expect("fixture payloads are padded to whole blocks");
}

/// How a fixture encrypts its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureEncryption {
    /// Stored as plaintext.
    None,
    /// Encrypted under the retail master key.
    Retail,
    /// Encrypted under the devkit master key.
    Devkit,
    /// Encrypted under a master key no loader knows, to exercise the wrong-key path.
    UnknownKey,
}

impl FixtureEncryption {
    /// Returns the master key, or `None` if the payload is plaintext.
    fn master_key(self) -> Option<[u8; 16]> {
        match self {
            FixtureEncryption::None => None,
            FixtureEncryption::Retail => Some(RETAIL_KEY),
            FixtureEncryption::Devkit => Some(DEVKIT_KEY),
            FixtureEncryption::UnknownKey => Some(*b"not-a-known-key!"),
        }
    }
}

/// How a fixture compresses its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureCompression {
    /// The payload is the image.
    None,
    /// Zero runs are left out of the payload.
    Basic,
    /// LZX with uncompressed blocks.
    LzxUncompressedBlocks,
    /// LZX with Huffman-coded verbatim blocks.
    LzxVerbatimBlocks,
    /// LZX using these exact chunks, valid or not, under a correct digest chain.
    LzxChunks(Vec<Vec<u8>>),
}

/// A run of pages for the security info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRun {
    /// The 4-bit kind: 1 code, 2 data, 3 read-only data.
    pub kind: u32,
    /// How many pages the run covers.
    pub pages: u32,
}

/// Value of an optional header being laid out.
enum OptionalValue {
    /// Stored inline in the directory entry.
    Inline(u32),
    /// Stored elsewhere in the headers; the directory entry holds its file offset.
    Data(Vec<u8>),
}

/// Describes a XEX2 file to generate.
#[derive(Debug, Clone)]
pub struct XexBuilder {
    /// The plaintext image.
    pub image: Vec<u8>,
    /// Module flags.
    pub module_flags: u32,
    /// Guest address stored in the security info.
    pub load_address: u32,
    /// Value of the image base optional header, if the file should have one.
    pub image_base_override: Option<u32>,
    /// Size of one page: `0x1000` or `0x10000`.
    pub page_size: u32,
    /// Page runs of the security info, or `None` for one code run over the whole image.
    pub page_runs: Option<Vec<PageRun>>,
    /// Value of the entry point optional header.
    pub entry_point: u32,
    /// Guest address of the XEX export table, stored in the security info.
    pub export_table: u32,
    /// Number of import libraries, stored in the security info.
    pub import_table_count: u32,
    /// More optional headers, as `(key, data)` for keys whose data lives outside the directory.
    pub extra_optional: Vec<(u32, Vec<u8>)>,
    /// How the payload is encrypted.
    pub encryption: FixtureEncryption,
    /// How the payload is compressed.
    pub compression: FixtureCompression,
    /// LZX window size.
    pub window_size: u32,
    /// How many LZX chunks each compressed block holds.
    pub chunks_per_block: usize,
}

/// The file position of one compressed block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLayout {
    /// File offset of the block.
    pub offset: usize,
    /// Size of the block.
    pub size: usize,
}

/// A generated XEX2 file and the offsets tests need to corrupt it precisely.
#[derive(Debug, Clone)]
pub struct BuiltXex {
    /// The whole file.
    pub bytes: Vec<u8>,
    /// File offset of the security info.
    pub security_offset: u32,
    /// Size of all headers, which is also the file offset of the payload.
    pub header_size: u32,
    /// The optional headers as `(key, directory entry offset, data offset)`.
    pub optional: Vec<(u32, usize, usize)>,
    /// The compressed blocks, if the payload has any.
    pub blocks: Vec<BlockLayout>,
}

impl BuiltXex {
    /// Returns the file offset of the directory entry for `key`.
    ///
    /// # Panics
    ///
    /// Panics if the file lacks that header, which is a bug in the test using it.
    pub fn optional_entry_offset(&self, key: u32) -> usize {
        self.optional_entry(key).1
    }

    /// Returns the file offset of the data of the optional header `key`.
    ///
    /// # Panics
    ///
    /// Panics if the file lacks that header, which is a bug in the test using it.
    pub fn optional_data_offset(&self, key: u32) -> usize {
        self.optional_entry(key).2
    }

    fn optional_entry(&self, key: u32) -> (u32, usize, usize) {
        *self
            .optional
            .iter()
            .find(|entry| entry.0 == key)
            .expect("fixture lacks this optional header")
    }
}

/// A payload ready to be placed after the headers.
struct Payload {
    bytes: Vec<u8>,
    format_info: Vec<u8>,
    blocks: Vec<BlockLayout>,
}

impl XexBuilder {
    /// Starts a plaintext, uncompressed title module with the given image.
    pub fn new(image: Vec<u8>) -> Self {
        Self {
            image,
            module_flags: 0x1,
            load_address: 0x8200_0000,
            image_base_override: None,
            page_size: 0x1_0000,
            page_runs: None,
            entry_point: 0x8201_0000,
            export_table: 0,
            import_table_count: 0,
            extra_optional: Vec::new(),
            encryption: FixtureEncryption::None,
            compression: FixtureCompression::None,
            window_size: 0x8000,
            chunks_per_block: 2,
        }
    }

    /// Generates the file.
    pub fn build(&self) -> BuiltXex {
        let mut payload = self.payload();
        if self.encryption.master_key().is_some() {
            payload.bytes.resize(align_up(payload.bytes.len(), 16), 0);
            encrypt_cbc(&SESSION_KEY, &mut payload.bytes);
        }
        let headers = self.optional_headers(payload.format_info);
        let mut built = self.assemble(&payload.bytes, headers);
        let start = built.header_size as usize;
        built.blocks = payload
            .blocks
            .iter()
            .map(|block| BlockLayout {
                offset: start + block.offset,
                size: block.size,
            })
            .collect();
        built
    }

    /// Compresses the image and lays out the file format info that describes the result.
    fn payload(&self) -> Payload {
        let chunks = match &self.compression {
            FixtureCompression::None => {
                return Payload {
                    bytes: self.image.clone(),
                    format_info: self.format_info(0, &[]),
                    blocks: Vec::new(),
                };
            }
            FixtureCompression::Basic => return self.basic_payload(),
            FixtureCompression::LzxUncompressedBlocks => lzx::encode_uncompressed(&self.image),
            FixtureCompression::LzxVerbatimBlocks => {
                lzx::encode_verbatim(&self.image, self.window_size)
            }
            FixtureCompression::LzxChunks(chunks) => chunks.clone(),
        };
        self.lzx_payload(&chunks)
    }

    /// Lays out the common start of the file format info, followed by `rest`.
    fn format_info(&self, compression: u16, rest: &[u8]) -> Vec<u8> {
        let encryption = u16::from(self.encryption != FixtureEncryption::None);
        let mut info = Vec::new();
        info.extend_from_slice(&(8 + rest.len() as u32).to_be_bytes());
        info.extend_from_slice(&encryption.to_be_bytes());
        info.extend_from_slice(&compression.to_be_bytes());
        info.extend_from_slice(rest);
        info
    }

    /// Splits the image into data and zero runs, at 16-byte boundaries so it can be encrypted.
    fn basic_payload(&self) -> Payload {
        const UNIT: usize = 16;
        const MIN_ZERO_RUN: usize = 0x100;
        let is_zero = |start: usize, len: usize| {
            self.image
                .get(start..start + len)
                .is_some_and(|bytes| bytes.iter().all(|&b| b == 0))
        };
        let mut bytes = Vec::new();
        let mut table = Vec::new();
        let mut position = 0;
        while position < self.image.len() {
            let data_start = position;
            while position < self.image.len() && !is_zero(position, MIN_ZERO_RUN) {
                position = (position + UNIT).min(self.image.len());
            }
            bytes.extend_from_slice(&self.image[data_start..position]);
            let zero_start = position;
            while is_zero(position, UNIT) {
                position += UNIT;
            }
            table.extend_from_slice(&((zero_start - data_start) as u32).to_be_bytes());
            table.extend_from_slice(&((position - zero_start) as u32).to_be_bytes());
        }
        Payload {
            bytes,
            format_info: self.format_info(1, &table),
            blocks: Vec::new(),
        }
    }

    /// Wraps LZX chunks into blocks, each with the size and digest of the next one.
    fn lzx_payload(&self, chunks: &[Vec<u8>]) -> Payload {
        let mut encoded: Vec<Vec<u8>> = Vec::new();
        let mut next_size = 0u32;
        let mut next_digest = [0; 20];
        for group in chunks.chunks(self.chunks_per_block.max(1)).rev() {
            let mut block = Vec::new();
            block.extend_from_slice(&next_size.to_be_bytes());
            block.extend_from_slice(&next_digest);
            for chunk in group {
                block.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                block.extend_from_slice(chunk);
            }
            block.extend_from_slice(&[0, 0]);
            // Real blocks are padded, so a parser has to trust the size rather than the zero size.
            block.resize(align_up(block.len(), 16), 0);
            next_size = block.len() as u32;
            next_digest = Sha1::digest(&block).into();
            encoded.push(block);
        }
        encoded.reverse();

        let mut rest = Vec::new();
        rest.extend_from_slice(&self.window_size.to_be_bytes());
        rest.extend_from_slice(&next_size.to_be_bytes());
        rest.extend_from_slice(&next_digest);

        let mut blocks = Vec::new();
        let mut bytes = Vec::new();
        for block in &encoded {
            blocks.push(BlockLayout {
                offset: bytes.len(),
                size: block.len(),
            });
            bytes.extend_from_slice(block);
        }
        Payload {
            bytes,
            format_info: self.format_info(2, &rest),
            blocks,
        }
    }

    /// Lists the optional headers, sorted by key as in real files.
    fn optional_headers(&self, format_info: Vec<u8>) -> Vec<(u32, OptionalValue)> {
        let mut pe_name = Vec::new();
        pe_name.extend_from_slice(&20u32.to_be_bytes());
        pe_name.extend_from_slice(b"synthetic.pe\0\0\0\0");

        let mut execution = Vec::new();
        for word in [0x1234_5678u32, 0x120D_804E, 0x1100_0000, 0x5A5A_07D1] {
            execution.extend_from_slice(&word.to_be_bytes());
        }
        execution.extend_from_slice(&[2, 0, 1, 1]);
        execution.extend_from_slice(&0xABCD_0001u32.to_be_bytes());

        let mut tls = Vec::new();
        for word in [64u32, 0x8201_0100, 0x20, 0x10] {
            tls.extend_from_slice(&word.to_be_bytes());
        }

        let mut headers = vec![
            (key::FILE_FORMAT_INFO, OptionalValue::Data(format_info)),
            (key::ENTRY_POINT, OptionalValue::Inline(self.entry_point)),
            (key::ORIGINAL_PE_NAME, OptionalValue::Data(pe_name)),
            (key::TLS_INFO, OptionalValue::Data(tls)),
            (key::DEFAULT_STACK_SIZE, OptionalValue::Inline(0x4_0000)),
            (key::SYSTEM_FLAGS, OptionalValue::Inline(0x400)),
            (key::EXECUTION_INFO, OptionalValue::Data(execution)),
        ];
        if let Some(base) = self.image_base_override {
            headers.push((key::IMAGE_BASE_ADDRESS, OptionalValue::Inline(base)));
        }
        for (key, data) in &self.extra_optional {
            headers.push((*key, OptionalValue::Data(data.clone())));
        }
        headers.sort_by_key(|header| header.0);
        headers
    }

    /// Concatenates the headers and the payload.
    fn assemble(&self, payload: &[u8], optional: Vec<(u32, OptionalValue)>) -> BuiltXex {
        let security_offset = 0x18 + optional.len() * 8;
        let security = self.security_info();
        let mut next_data = security_offset + security.len();

        let mut directory = Vec::new();
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for (index, (key, value)) in optional.iter().enumerate() {
            let entry_offset = 0x18 + index * 8;
            let (word, data_offset) = match value {
                OptionalValue::Inline(value) => (*value, entry_offset + 4),
                OptionalValue::Data(bytes) => {
                    let offset = next_data;
                    data.extend_from_slice(bytes);
                    next_data += bytes.len();
                    (offset as u32, offset)
                }
            };
            directory.extend_from_slice(&key.to_be_bytes());
            directory.extend_from_slice(&word.to_be_bytes());
            offsets.push((*key, entry_offset, data_offset));
        }

        let header_size = align_up(next_data, 16);
        let mut bytes = Vec::with_capacity(header_size + payload.len());
        bytes.extend_from_slice(&XEX2_MAGIC.to_be_bytes());
        bytes.extend_from_slice(&self.module_flags.to_be_bytes());
        bytes.extend_from_slice(&(header_size as u32).to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&(security_offset as u32).to_be_bytes());
        bytes.extend_from_slice(&(optional.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&directory);
        bytes.extend_from_slice(&security);
        bytes.extend_from_slice(&data);
        bytes.resize(header_size, 0);
        bytes.extend_from_slice(payload);

        BuiltXex {
            bytes,
            security_offset: security_offset as u32,
            header_size: header_size as u32,
            optional: offsets,
            blocks: Vec::new(),
        }
    }

    /// Returns the page runs of the security info.
    fn runs(&self) -> Vec<PageRun> {
        self.page_runs.clone().unwrap_or_else(|| {
            vec![PageRun {
                kind: 1,
                pages: self.image.len() as u32 / self.page_size,
            }]
        })
    }

    /// Lays out the security info, with the digest chain over the image's pages.
    fn security_info(&self) -> Vec<u8> {
        const FIXED_SIZE: usize = 0x184;
        const DESCRIPTOR_SIZE: usize = 24;
        let runs = self.runs();
        let size = FIXED_SIZE + DESCRIPTOR_SIZE * runs.len();
        let mut info = vec![0; size];
        be32(&mut info, 0x0, size as u32);
        be32(&mut info, 0x4, self.image.len() as u32);
        info[0x8..0x108].fill(0xA5);
        be32(&mut info, 0x108, 0x174);
        let flags = if self.page_size == 0x1000 {
            ImageFlags::PAGE_SIZE_4KB
        } else {
            0
        };
        be32(&mut info, 0x10C, flags);
        be32(&mut info, 0x110, self.load_address);
        let mut session_key = SESSION_KEY;
        if let Some(master) = self.encryption.master_key() {
            encrypt_cbc(&master, &mut session_key);
        }
        info[0x150..0x160].copy_from_slice(&session_key);
        be32(&mut info, 0x128, self.import_table_count);
        be32(&mut info, 0x160, self.export_table);
        be32(&mut info, 0x178, 0xFFFF_FFFF);
        be32(&mut info, 0x17C, 0xFFFF_FFFF);
        be32(&mut info, 0x180, runs.len() as u32);
        let digest = self.page_digest_chain(&runs, &mut info[FIXED_SIZE..]);
        info[0x114..0x128].copy_from_slice(&digest);
        info
    }

    /// Writes the descriptors and returns the digest of the first run. Each descriptor holds the
    /// digest of the next run, which in turn covers that run's descriptor, so the walk goes
    /// backwards.
    fn page_digest_chain(&self, runs: &[PageRun], descriptors: &mut [u8]) -> [u8; 20] {
        const DESCRIPTOR_SIZE: usize = 24;
        let mut end = self.image.len();
        let mut digest = [0; 20];
        for (index, run) in runs.iter().enumerate().rev() {
            let size = (run.pages * self.page_size) as usize;
            let start = end.saturating_sub(size);
            let descriptor = &mut descriptors[index * DESCRIPTOR_SIZE..][..DESCRIPTOR_SIZE];
            descriptor[..4].copy_from_slice(&((run.pages << 4) | run.kind).to_be_bytes());
            descriptor[4..].copy_from_slice(&digest);
            let mut hasher = Sha1::new();
            hasher.update(&self.image[start..end]);
            hasher.update(&*descriptor);
            digest = hasher.finalize().into();
            end = start;
        }
        digest
    }
}
