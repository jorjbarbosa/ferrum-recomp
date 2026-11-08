// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The XEX2 file header: fixed fields, the optional header directory and the security info.
//!
//! Layouts follow `src/xenia/kernel/util/xex2_info.h` in Xenia.

use std::fmt;

use crate::error::{ErrorKind, Result};
use crate::reader::Reader;

/// The file signature, `XEX2` in ASCII.
pub const XEX2_MAGIC: u32 = 0x5845_5832;

/// Largest image accepted. The console has 512 MiB of RAM and devkits 1 GiB, so a larger size is
/// corruption, and rejecting it early bounds what a bad file can make the parser allocate.
pub const MAX_IMAGE_SIZE: u32 = 0x4000_0000;

/// Size of the fixed part of the file header.
const FIXED_HEADER_SIZE: u64 = 0x18;
/// Size of one entry of the optional header directory.
const OPTIONAL_ENTRY_SIZE: u64 = 8;
/// Size of the security info up to, but not including, the page descriptors.
const SECURITY_INFO_FIXED_SIZE: u64 = 0x184;
/// Size of one page descriptor.
const PAGE_DESCRIPTOR_SIZE: u64 = 24;

/// Offsets of the security info fields, relative to its start.
pub(crate) mod security_field {
    pub(crate) const INFO_SIZE: u64 = 0x0;
    pub(crate) const IMAGE_SIZE: u64 = 0x4;
    pub(crate) const IMAGE_FLAGS: u64 = 0x10C;
    pub(crate) const LOAD_ADDRESS: u64 = 0x110;
    pub(crate) const IMAGE_DIGEST: u64 = 0x114;
    pub(crate) const IMPORT_TABLE_COUNT: u64 = 0x128;
    pub(crate) const AES_KEY: u64 = 0x150;
    pub(crate) const EXPORT_TABLE: u64 = 0x160;
    pub(crate) const REGION: u64 = 0x178;
    pub(crate) const ALLOWED_MEDIA_TYPES: u64 = 0x17C;
    pub(crate) const PAGE_DESCRIPTOR_COUNT: u64 = 0x180;
}

/// Keys of the optional headers this crate reads.
///
/// The low byte of a key describes its value: `0x00` and `0x01` mean the value is stored inline in
/// the directory, `0xFF` means it points to a block that starts with its own size, and any other
/// `n` means it points to `n` 32-bit words.
pub mod key {
    /// Resource table.
    pub const RESOURCE_INFO: u32 = 0x0000_02FF;
    /// Encryption and compression of the payload.
    pub const FILE_FORMAT_INFO: u32 = 0x0000_03FF;
    /// Base address the module was linked at.
    pub const ORIGINAL_BASE_ADDRESS: u32 = 0x0001_0001;
    /// Guest address of the entry point.
    pub const ENTRY_POINT: u32 = 0x0001_0100;
    /// Guest address the image loads at.
    pub const IMAGE_BASE_ADDRESS: u32 = 0x0001_0201;
    /// Import libraries.
    pub const IMPORT_LIBRARIES: u32 = 0x0001_03FF;
    /// File name of the PE the module was built from.
    pub const ORIGINAL_PE_NAME: u32 = 0x0001_83FF;
    /// Thread-local storage layout.
    pub const TLS_INFO: u32 = 0x0002_0104;
    /// Default stack size.
    pub const DEFAULT_STACK_SIZE: u32 = 0x0002_0200;
    /// Default heap size.
    pub const DEFAULT_HEAP_SIZE: u32 = 0x0002_0401;
    /// System privileges.
    pub const SYSTEM_FLAGS: u32 = 0x0003_0000;
    /// Title id, versions and disc numbering.
    pub const EXECUTION_INFO: u32 = 0x0004_0006;
    /// PE export directory location.
    pub const EXPORTS_BY_NAME: u32 = 0x00E1_0402;
}

/// Returns the name of a known optional header key.
pub fn key_name(key: u32) -> Option<&'static str> {
    Some(match key {
        key::RESOURCE_INFO => "resource_info",
        key::FILE_FORMAT_INFO => "file_format_info",
        0x0000_05FF => "delta_patch_descriptor",
        0x0000_0405 => "base_reference",
        0x0000_80FF => "bounding_path",
        0x0000_8105 => "device_id",
        key::ORIGINAL_BASE_ADDRESS => "original_base_address",
        key::ENTRY_POINT => "entry_point",
        key::IMAGE_BASE_ADDRESS => "image_base_address",
        key::IMPORT_LIBRARIES => "import_libraries",
        0x0001_8002 => "checksum_timestamp",
        0x0001_8102 => "enabled_for_callcap",
        0x0001_8200 => "enabled_for_fastcap",
        key::ORIGINAL_PE_NAME => "original_pe_name",
        0x0002_00FF => "static_libraries",
        key::TLS_INFO => "tls_info",
        key::DEFAULT_STACK_SIZE => "default_stack_size",
        0x0002_0301 => "default_filesystem_cache_size",
        key::DEFAULT_HEAP_SIZE => "default_heap_size",
        0x0002_8002 => "page_heap_size_and_flags",
        key::SYSTEM_FLAGS => "system_flags",
        key::EXECUTION_INFO => "execution_info",
        0x0004_0201 => "title_workspace_size",
        0x0004_0310 => "game_ratings",
        0x0004_0404 => "lan_key",
        0x0004_05FF => "xbox360_logo",
        0x0004_06FF => "multidisc_media_ids",
        0x0004_07FF => "alternate_title_ids",
        0x0004_0801 => "additional_title_memory",
        key::EXPORTS_BY_NAME => "exports_by_name",
        _ => return None,
    })
}

/// The module flags of the file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleFlags(pub u32);

impl ModuleFlags {
    /// Flag names, by bit value.
    const NAMES: [(u32, &'static str); 8] = [
        (0x01, "title"),
        (0x02, "exports_to_title"),
        (0x04, "system_debugger"),
        (0x08, "dll"),
        (0x10, "module_patch"),
        (0x20, "patch_full"),
        (0x40, "patch_delta"),
        (0x80, "user_mode"),
    ];
    /// The bits that mark a `.xexp` patch.
    const PATCH_MASK: u32 = 0x70;

    /// Returns whether the module is a `.xexp` patch rather than a complete image.
    pub fn is_patch(self) -> bool {
        self.0 & Self::PATCH_MASK != 0
    }

    /// Returns the names of the flags that are set.
    pub fn names(self) -> Vec<&'static str> {
        names_of(self.0, &Self::NAMES)
    }
}

/// The image flags of the security info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageFlags(pub u32);

impl ImageFlags {
    /// Set when the image uses 4 KiB pages; otherwise it uses 64 KiB pages.
    pub const PAGE_SIZE_4KB: u32 = 0x1000_0000;
    /// Flag names, by bit value.
    const NAMES: [(u32, &'static str); 18] = [
        (0x0000_0002, "manufacturing_utility"),
        (0x0000_0004, "manufacturing_support_tools"),
        (0x0000_0008, "xgd2_media_only"),
        (0x0000_0100, "cardea_key"),
        (0x0000_0200, "xeika_key"),
        (0x0000_0400, "usermode_title"),
        (0x0000_0800, "usermode_system"),
        (0x0000_1000, "orange0"),
        (0x0000_2000, "orange1"),
        (0x0000_4000, "orange2"),
        (0x0001_0000, "iptv_signup_application"),
        (0x0002_0000, "iptv_title_application"),
        (0x0400_0000, "keyvault_privileges_required"),
        (0x0800_0000, "online_activation_required"),
        (Self::PAGE_SIZE_4KB, "page_size_4kb"),
        (0x2000_0000, "region_free"),
        (0x4000_0000, "revocation_check_optional"),
        (0x8000_0000, "revocation_check_required"),
    ];

    /// Returns the names of the flags that are set.
    pub fn names(self) -> Vec<&'static str> {
        names_of(self.0, &Self::NAMES)
    }
}

/// Lists the names whose bit is set in `flags`, in table order.
fn names_of(flags: u32, table: &[(u32, &'static str)]) -> Vec<&'static str> {
    table
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|&(_, name)| name)
        .collect()
}

/// A version number packed as `major:4 minor:4 build:16 qfe:8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version(pub u32);

impl Version {
    /// Returns the major version.
    pub fn major(self) -> u32 {
        self.0 >> 28
    }

    /// Returns the minor version.
    pub fn minor(self) -> u32 {
        (self.0 >> 24) & 0xF
    }

    /// Returns the build number.
    pub fn build(self) -> u32 {
        (self.0 >> 8) & 0xFFFF
    }

    /// Returns the quick-fix number.
    pub fn qfe(self) -> u32 {
        self.0 & 0xFF
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (major, minor) = (self.major(), self.minor());
        write!(f, "{major}.{minor}.{}.{}", self.build(), self.qfe())
    }
}

/// One entry of the optional header directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionalHeader {
    /// What the header holds; see [`key`].
    pub key: u32,
    /// The inline value, or the file offset of the data, depending on the key's low byte.
    pub value: u32,
    /// File offset of this directory entry.
    pub entry_offset: u32,
}

/// How the payload is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// The payload is plaintext.
    None,
    /// The payload is AES-128-CBC encrypted.
    Normal,
}

/// One run of a "basic" compressed payload: bytes present in the file, then zeros that are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicBlock {
    /// Bytes stored in the file.
    pub data_size: u32,
    /// Zero bytes that follow in the image.
    pub zero_size: u32,
}

/// How the payload is compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compression {
    /// The payload is the image.
    None,
    /// The payload omits runs of zeros, described by these blocks.
    Basic(Vec<BasicBlock>),
    /// The payload is an LZX stream split into hash-chained blocks.
    Normal {
        /// LZX window size in bytes.
        window_size: u32,
        /// Size of the first compressed block.
        first_block_size: u32,
        /// SHA-1 of the first compressed block.
        first_block_digest: [u8; 20],
    },
}

/// The file format info optional header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFormat {
    /// How the payload is encrypted.
    pub encryption: Encryption,
    /// How the payload is compressed.
    pub compression: Compression,
}

/// The execution info optional header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionInfo {
    /// Media id.
    pub media_id: u32,
    /// Module version.
    pub version: Version,
    /// Base version of the module.
    pub base_version: Version,
    /// Title id.
    pub title_id: u32,
    /// Target platform.
    pub platform: u8,
    /// Executable table.
    pub executable_table: u8,
    /// Number of this disc.
    pub disc_number: u8,
    /// Number of discs of the title.
    pub disc_count: u8,
    /// Save game id.
    pub savegame_id: u32,
}

/// The thread-local storage layout from the TLS info optional header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsInfo {
    /// Number of TLS slots.
    pub slot_count: u32,
    /// Guest address of the initial TLS data.
    pub raw_data_address: u32,
    /// Total size of the TLS data.
    pub data_size: u32,
    /// Size of the initialized part of the TLS data.
    pub raw_data_size: u32,
}

/// A resource embedded in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    /// Name of the resource.
    pub name: String,
    /// Guest address of the resource.
    pub address: u32,
    /// Size of the resource.
    pub size: u32,
}

/// What a run of image pages holds, as stated by the security info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageKind {
    /// Code.
    Code,
    /// Writable data.
    Data,
    /// Read-only data.
    ReadOnlyData,
    /// A value the format does not define.
    Unknown(u8),
}

/// One descriptor of the security info: a run of pages of the same kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageDescriptor {
    /// The packed `page_count:28 kind:4` word, as stored.
    pub raw: u32,
    /// SHA-1 of the next run of pages followed by the next descriptor.
    pub next_digest: [u8; 20],
}

impl PageDescriptor {
    /// Returns what the pages hold.
    pub fn kind(&self) -> PageKind {
        // The mask keeps 4 bits, so the truncation loses nothing.
        match (self.raw & 0xF) as u8 {
            1 => PageKind::Code,
            2 => PageKind::Data,
            3 => PageKind::ReadOnlyData,
            other => PageKind::Unknown(other),
        }
    }

    /// Returns how many pages the run covers.
    pub fn page_count(&self) -> u32 {
        self.raw >> 4
    }
}

/// The security info: the part of the header the console verifies with an RSA signature.
///
/// The signature itself is not checked, since recompilation does not depend on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityInfo {
    /// Size of the security info, as stated by its first field.
    pub info_size: u32,
    /// Size of the decompressed image.
    pub image_size: u32,
    /// Image flags.
    pub image_flags: ImageFlags,
    /// Guest address the image loads at.
    pub load_address: u32,
    /// SHA-1 of the first run of pages followed by the first descriptor.
    pub image_digest: [u8; 20],
    /// Number of import libraries.
    pub import_table_count: u32,
    /// Session key, encrypted with the console's master key.
    pub encrypted_key: [u8; 16],
    /// Guest address of the XEX export table, or zero if there is none.
    pub export_table: u32,
    /// Allowed regions.
    pub region: u32,
    /// Allowed media types.
    pub allowed_media_types: u32,
    /// Page descriptors, in image order.
    pub page_descriptors: Vec<PageDescriptor>,
}

impl SecurityInfo {
    /// Returns the size in bytes of one page of the image.
    pub fn page_size(&self) -> u32 {
        if self.image_flags.0 & ImageFlags::PAGE_SIZE_4KB != 0 {
            0x1000
        } else {
            0x1_0000
        }
    }
}

/// The parsed file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Module flags.
    pub module_flags: ModuleFlags,
    /// Size of all headers; the payload starts at this file offset.
    pub header_size: u32,
    /// File offset of the security info.
    pub security_offset: u32,
    /// The optional header directory, in file order.
    pub optional_headers: Vec<OptionalHeader>,
    /// Encryption and compression of the payload.
    pub file_format: FileFormat,
    /// Guest address of the entry point.
    pub entry_point: Option<u32>,
    /// Guest address the image loads at, overriding the security info.
    pub image_base_address: Option<u32>,
    /// Base address the module was linked at.
    pub original_base_address: Option<u32>,
    /// Default stack size.
    pub default_stack_size: Option<u32>,
    /// Default heap size.
    pub default_heap_size: Option<u32>,
    /// System privileges.
    pub system_flags: Option<u32>,
    /// File name of the PE the module was built from.
    pub original_pe_name: Option<String>,
    /// Title id, versions and disc numbering.
    pub execution_info: Option<ExecutionInfo>,
    /// Thread-local storage layout.
    pub tls: Option<TlsInfo>,
    /// Resources embedded in the image.
    pub resources: Vec<Resource>,
    /// The security info.
    pub security: SecurityInfo,
}

impl Header {
    /// Parses and validates all headers of a XEX2 file.
    pub fn parse(file: &[u8]) -> Result<Self> {
        let reader = Reader::file(file);
        check_magic(&reader)?;
        let module_flags = read_module_flags(&reader)?;
        let header_size = read_header_size(&reader)?;
        // From here on nothing may reach past the headers.
        let reader = Reader::file(reader.bytes(0, header_size.into(), "header.header_size")?);
        let security_offset = reader.be_u32(0x10, "header.security_offset")?;
        let optional_headers = read_directory(&reader)?;
        let security = read_security_info(&reader, security_offset)?;
        let optional = Optional {
            reader,
            entries: &optional_headers,
        };
        Ok(Self {
            module_flags,
            header_size,
            security_offset,
            file_format: read_file_format(&optional)?,
            entry_point: optional.inline(key::ENTRY_POINT, "optional.entry_point")?,
            image_base_address: optional
                .inline(key::IMAGE_BASE_ADDRESS, "optional.image_base_address")?,
            original_base_address: optional
                .inline(key::ORIGINAL_BASE_ADDRESS, "optional.original_base_address")?,
            default_stack_size: optional
                .inline(key::DEFAULT_STACK_SIZE, "optional.default_stack_size")?,
            default_heap_size: optional
                .inline(key::DEFAULT_HEAP_SIZE, "optional.default_heap_size")?,
            system_flags: optional.inline(key::SYSTEM_FLAGS, "optional.system_flags")?,
            original_pe_name: read_original_pe_name(&optional)?,
            execution_info: read_execution_info(&optional)?,
            tls: read_tls_info(&optional)?,
            resources: read_resources(&optional)?,
            optional_headers,
            security,
        })
    }

    /// Returns the guest address the image loads at.
    ///
    /// The image base optional header wins over the security info, as in Xenia's `XexModule::Load`.
    pub fn base_address(&self) -> u32 {
        self.image_base_address
            .unwrap_or(self.security.load_address)
    }

    /// Returns the file offset and bytes of an optional header, or `None` if the file lacks it.
    ///
    /// Inline headers yield the four value bytes of their directory entry. Size-prefixed headers
    /// include the size field. `file` must be the file given to [`Header::parse`].
    pub fn optional_data<'a>(&self, file: &'a [u8], key: u32) -> Result<Option<(u64, &'a [u8])>> {
        let end = usize::try_from(self.header_size).unwrap_or(usize::MAX);
        let optional = Optional {
            reader: Reader::file(file.get(..end).unwrap_or(file)),
            entries: &self.optional_headers,
        };
        optional.locate(key, "optional_header")
    }
}

/// Checks the file signature.
fn check_magic(reader: &Reader<'_>) -> Result<()> {
    let found = reader.be_u32(0, "header.magic")?;
    if found == XEX2_MAGIC {
        return Ok(());
    }
    let expected = XEX2_MAGIC;
    let kind = ErrorKind::BadMagic { expected, found };
    Err(reader.error(0, "header.magic", kind))
}

/// Reads the module flags and rejects patches, which are out of scope.
fn read_module_flags(reader: &Reader<'_>) -> Result<ModuleFlags> {
    let flags = ModuleFlags(reader.be_u32(4, "header.module_flags")?);
    if !flags.is_patch() {
        return Ok(flags);
    }
    let kind = ErrorKind::Unsupported {
        value: flags.0.into(),
        reason: "the file is a .xexp patch, which is not supported",
    };
    Err(reader.error(4, "header.module_flags", kind))
}

/// Reads the header size and checks it covers the fixed fields.
fn read_header_size(reader: &Reader<'_>) -> Result<u32> {
    let size = reader.be_u32(8, "header.header_size")?;
    if u64::from(size) >= FIXED_HEADER_SIZE {
        return Ok(size);
    }
    let kind = ErrorKind::InvalidValue {
        value: size.into(),
        reason: "smaller than the fixed header",
    };
    Err(reader.error(8, "header.header_size", kind))
}

/// Reads the optional header directory.
fn read_directory(reader: &Reader<'_>) -> Result<Vec<OptionalHeader>> {
    let count = u64::from(reader.be_u32(0x14, "header.optional_header_count")?);
    reader.bytes(
        FIXED_HEADER_SIZE,
        count * OPTIONAL_ENTRY_SIZE,
        "header.optional_headers",
    )?;
    (0..count)
        .map(|index| {
            let offset = FIXED_HEADER_SIZE + index * OPTIONAL_ENTRY_SIZE;
            Ok(OptionalHeader {
                key: reader.be_u32(offset, "header.optional_headers.key")?,
                value: reader.be_u32(offset + 4, "header.optional_headers.value")?,
                // The entry lies within `header_size`, a 32-bit value, so the offset fits.
                entry_offset: offset as u32,
            })
        })
        .collect()
}

/// Reads the security info at `offset`.
fn read_security_info(reader: &Reader<'_>, offset: u32) -> Result<SecurityInfo> {
    use security_field as f;
    let base = u64::from(offset);
    reader.bytes(base, SECURITY_INFO_FIXED_SIZE, "security_info")?;
    Ok(SecurityInfo {
        info_size: read_security_info_size(reader, base)?,
        image_size: read_image_size(reader, base)?,
        image_flags: ImageFlags(reader.be_u32(base + f::IMAGE_FLAGS, "security_info.image_flags")?),
        load_address: reader.be_u32(base + f::LOAD_ADDRESS, "security_info.load_address")?,
        image_digest: reader.array(base + f::IMAGE_DIGEST, "security_info.image_digest")?,
        import_table_count: reader.be_u32(
            base + f::IMPORT_TABLE_COUNT,
            "security_info.import_table_count",
        )?,
        encrypted_key: reader.array(base + f::AES_KEY, "security_info.aes_key")?,
        export_table: reader.be_u32(base + f::EXPORT_TABLE, "security_info.export_table")?,
        region: reader.be_u32(base + f::REGION, "security_info.region")?,
        allowed_media_types: reader.be_u32(
            base + f::ALLOWED_MEDIA_TYPES,
            "security_info.allowed_media_types",
        )?,
        page_descriptors: read_page_descriptors(reader, base)?,
    })
}

/// Reads the size field of the security info; the console rejects values below the fixed part.
fn read_security_info_size(reader: &Reader<'_>, base: u64) -> Result<u32> {
    let offset = base + security_field::INFO_SIZE;
    let size = reader.be_u32(offset, "security_info.info_size")?;
    if u64::from(size) >= SECURITY_INFO_FIXED_SIZE {
        return Ok(size);
    }
    let kind = ErrorKind::InvalidValue {
        value: size.into(),
        reason: "smaller than the fixed part of the security info",
    };
    Err(reader.error(offset, "security_info.info_size", kind))
}

/// Reads the image size and rejects values no real image can have.
fn read_image_size(reader: &Reader<'_>, base: u64) -> Result<u32> {
    let offset = base + security_field::IMAGE_SIZE;
    let size = reader.be_u32(offset, "security_info.image_size")?;
    if size != 0 && size <= MAX_IMAGE_SIZE {
        return Ok(size);
    }
    let kind = ErrorKind::InvalidValue {
        value: size.into(),
        reason: "must be non-zero and at most 1 GiB",
    };
    Err(reader.error(offset, "security_info.image_size", kind))
}

/// Reads the page descriptors at the end of the security info.
fn read_page_descriptors(reader: &Reader<'_>, base: u64) -> Result<Vec<PageDescriptor>> {
    let count_offset = base + security_field::PAGE_DESCRIPTOR_COUNT;
    let count = u64::from(reader.be_u32(count_offset, "security_info.page_descriptor_count")?);
    let table = base + SECURITY_INFO_FIXED_SIZE;
    reader.bytes(
        table,
        count * PAGE_DESCRIPTOR_SIZE,
        "security_info.page_descriptors",
    )?;
    (0..count)
        .map(|index| {
            let offset = table + index * PAGE_DESCRIPTOR_SIZE;
            Ok(PageDescriptor {
                raw: reader.be_u32(offset, "security_info.page_descriptors.value")?,
                next_digest: reader.array(offset + 4, "security_info.page_descriptors.digest")?,
            })
        })
        .collect()
}

/// Access to the optional headers of a file.
struct Optional<'a, 'h> {
    reader: Reader<'a>,
    entries: &'h [OptionalHeader],
}

impl<'a> Optional<'a, '_> {
    /// Finds a header and returns the file offset and bytes of its data.
    fn locate(&self, key: u32, field: &'static str) -> Result<Option<(u64, &'a [u8])>> {
        let Some(entry) = self.entries.iter().find(|entry| entry.key == key) else {
            return Ok(None);
        };
        let (offset, len) = match key & 0xFF {
            0x00 | 0x01 => (u64::from(entry.entry_offset) + 4, 4),
            0xFF => {
                let offset = u64::from(entry.value);
                (offset, self.size_prefix(offset, field)?)
            }
            words => (u64::from(entry.value), u64::from(words) * 4),
        };
        Ok(Some((offset, self.reader.bytes(offset, len, field)?)))
    }

    /// Reads the size field that starts a size-prefixed header.
    fn size_prefix(&self, offset: u64, field: &'static str) -> Result<u64> {
        let size = self.reader.be_u32(offset, field)?;
        if size >= 4 {
            return Ok(size.into());
        }
        let kind = ErrorKind::InvalidValue {
            value: size.into(),
            reason: "a size-prefixed header must include its own size field",
        };
        Err(self.reader.error(offset, field, kind))
    }

    /// Reads a header whose value is a single inline 32-bit word.
    fn inline(&self, key: u32, field: &'static str) -> Result<Option<u32>> {
        let Some((offset, _)) = self.locate(key, field)? else {
            return Ok(None);
        };
        self.reader.be_u32(offset, field).map(Some)
    }
}

/// Reads the required file format info.
fn read_file_format(optional: &Optional<'_, '_>) -> Result<FileFormat> {
    const FIELD: &str = "optional.file_format_info";
    let reader = &optional.reader;
    let Some((base, data)) = optional.locate(key::FILE_FORMAT_INFO, FIELD)? else {
        return Err(reader.error(0x14, FIELD, ErrorKind::Missing));
    };
    let size = data.len() as u64;
    if size < 8 {
        let kind = ErrorKind::InvalidValue {
            value: size,
            reason: "too small to hold the encryption and compression types",
        };
        return Err(reader.error(base, FIELD, kind));
    }
    Ok(FileFormat {
        encryption: read_encryption(reader, base)?,
        compression: read_compression(reader, base, size)?,
    })
}

/// Reads the encryption type of the file format info at `base`.
fn read_encryption(reader: &Reader<'_>, base: u64) -> Result<Encryption> {
    const FIELD: &str = "file_format_info.encryption_type";
    match reader.be_u16(base + 4, FIELD)? {
        0 => Ok(Encryption::None),
        1 => Ok(Encryption::Normal),
        other => {
            let kind = ErrorKind::InvalidValue {
                value: other.into(),
                reason: "not a known encryption type",
            };
            Err(reader.error(base + 4, FIELD, kind))
        }
    }
}

/// Reads the compression part of the file format info at `base`, which is `size` bytes long.
fn read_compression(reader: &Reader<'_>, base: u64, size: u64) -> Result<Compression> {
    const FIELD: &str = "file_format_info.compression_type";
    match reader.be_u16(base + 6, FIELD)? {
        0 => Ok(Compression::None),
        1 => read_basic_blocks(reader, base, size).map(Compression::Basic),
        2 => read_normal_compression(reader, base, size),
        3 => {
            let kind = ErrorKind::Unsupported {
                value: 3,
                reason: "delta compression only appears in .xexp patches",
            };
            Err(reader.error(base + 6, FIELD, kind))
        }
        other => {
            let kind = ErrorKind::InvalidValue {
                value: other.into(),
                reason: "not a known compression type",
            };
            Err(reader.error(base + 6, FIELD, kind))
        }
    }
}

/// Reads the blocks of a "basic" payload, which fill the file format info after its first 8 bytes.
fn read_basic_blocks(reader: &Reader<'_>, base: u64, size: u64) -> Result<Vec<BasicBlock>> {
    const FIRST_BLOCK: u64 = 8;
    const BLOCK_SIZE: u64 = 8;
    let count = size.saturating_sub(FIRST_BLOCK) / BLOCK_SIZE;
    (0..count)
        .map(|index| {
            let offset = base + FIRST_BLOCK + index * BLOCK_SIZE;
            Ok(BasicBlock {
                data_size: reader.be_u32(offset, "file_format_info.basic_block.data_size")?,
                zero_size: reader.be_u32(offset + 4, "file_format_info.basic_block.zero_size")?,
            })
        })
        .collect()
}

/// Reads the window size and first block of an LZX payload.
fn read_normal_compression(reader: &Reader<'_>, base: u64, size: u64) -> Result<Compression> {
    const NORMAL_INFO_SIZE: u64 = 36;
    if size < NORMAL_INFO_SIZE {
        let kind = ErrorKind::InvalidValue {
            value: size,
            reason: "too small for LZX compression info",
        };
        return Err(reader.error(base, "file_format_info.info_size", kind));
    }
    Ok(Compression::Normal {
        window_size: read_window_size(reader, base)?,
        first_block_size: reader.be_u32(base + 12, "file_format_info.first_block_size")?,
        first_block_digest: reader.array(base + 16, "file_format_info.first_block_digest")?,
    })
}

/// Reads the LZX window size, a power of two between the limits of the format.
fn read_window_size(reader: &Reader<'_>, base: u64) -> Result<u32> {
    const FIELD: &str = "file_format_info.window_size";
    let size = reader.be_u32(base + 8, FIELD)?;
    if size.is_power_of_two() && (0x8000..=0x200_0000).contains(&size) {
        return Ok(size);
    }
    let kind = ErrorKind::InvalidValue {
        value: size.into(),
        reason: "an LZX window is a power of two from 32 KiB to 32 MiB",
    };
    Err(reader.error(base + 8, FIELD, kind))
}

/// Reads the PE file name, a size-prefixed string that may be padded with NUL bytes.
fn read_original_pe_name(optional: &Optional<'_, '_>) -> Result<Option<String>> {
    let located = optional.locate(key::ORIGINAL_PE_NAME, "optional.original_pe_name")?;
    Ok(located.map(|(_, data)| {
        let text = data.get(4..).unwrap_or_default();
        let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
        String::from_utf8_lossy(&text[..end]).into_owned()
    }))
}

/// Reads the execution info.
fn read_execution_info(optional: &Optional<'_, '_>) -> Result<Option<ExecutionInfo>> {
    const FIELD: &str = "optional.execution_info";
    let Some((base, _)) = optional.locate(key::EXECUTION_INFO, FIELD)? else {
        return Ok(None);
    };
    let r = &optional.reader;
    let [platform, executable_table, disc_number, disc_count] = r.array(base + 0x10, FIELD)?;
    Ok(Some(ExecutionInfo {
        media_id: r.be_u32(base, FIELD)?,
        version: Version(r.be_u32(base + 4, FIELD)?),
        base_version: Version(r.be_u32(base + 8, FIELD)?),
        title_id: r.be_u32(base + 0xC, FIELD)?,
        platform,
        executable_table,
        disc_number,
        disc_count,
        savegame_id: r.be_u32(base + 0x14, FIELD)?,
    }))
}

/// Reads the TLS info.
fn read_tls_info(optional: &Optional<'_, '_>) -> Result<Option<TlsInfo>> {
    const FIELD: &str = "optional.tls_info";
    let Some((base, _)) = optional.locate(key::TLS_INFO, FIELD)? else {
        return Ok(None);
    };
    let r = &optional.reader;
    Ok(Some(TlsInfo {
        slot_count: r.be_u32(base, FIELD)?,
        raw_data_address: r.be_u32(base + 4, FIELD)?,
        data_size: r.be_u32(base + 8, FIELD)?,
        raw_data_size: r.be_u32(base + 0xC, FIELD)?,
    }))
}

/// Reads the resource table: 16-byte entries after the size prefix.
fn read_resources(optional: &Optional<'_, '_>) -> Result<Vec<Resource>> {
    const FIELD: &str = "optional.resource_info";
    const ENTRY_SIZE: u64 = 16;
    let Some((base, data)) = optional.locate(key::RESOURCE_INFO, FIELD)? else {
        return Ok(Vec::new());
    };
    let r = &optional.reader;
    (0..(data.len() as u64 - 4) / ENTRY_SIZE)
        .map(|index| {
            let offset = base + 4 + index * ENTRY_SIZE;
            let name: [u8; 8] = r.array(offset, FIELD)?;
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            Ok(Resource {
                name: String::from_utf8_lossy(&name[..end]).into_owned(),
                address: r.be_u32(offset + 8, FIELD)?,
                size: r.be_u32(offset + 12, FIELD)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Location;
    use crate::fixtures::{FixtureCompression, XexBuilder, be32};

    fn sample() -> Vec<u8> {
        XexBuilder::new(vec![0; 0x1_0000]).build().bytes
    }

    #[test]
    fn parses_fixed_fields_security_info_and_optional_headers() {
        let built = XexBuilder::new(vec![0; 0x2_0000]).build();
        let header = Header::parse(&built.bytes).unwrap();

        assert_eq!(header.module_flags, ModuleFlags(0x1));
        assert_eq!(header.module_flags.names(), ["title"]);
        assert!(!header.module_flags.is_patch());
        assert_eq!(header.header_size, built.header_size);
        assert_eq!(header.security_offset, built.security_offset);

        let security = &header.security;
        assert_eq!(security.image_size, 0x2_0000);
        assert_eq!(security.load_address, 0x8200_0000);
        assert_eq!(security.page_size(), 0x1_0000);
        assert_eq!(security.region, 0xFFFF_FFFF);
        assert_eq!(security.page_descriptors.len(), 1);
        let descriptor = &security.page_descriptors[0];
        assert_eq!(descriptor.kind(), PageKind::Code);
        assert_eq!(descriptor.page_count(), 2);

        assert_eq!(header.entry_point, Some(0x8201_0000));
        assert_eq!(header.base_address(), 0x8200_0000);
        assert_eq!(header.default_stack_size, Some(0x4_0000));
        assert_eq!(header.original_pe_name.as_deref(), Some("synthetic.pe"));
        assert_eq!(
            header.tls,
            Some(TlsInfo {
                slot_count: 64,
                raw_data_address: 0x8201_0100,
                data_size: 0x20,
                raw_data_size: 0x10,
            })
        );
        let execution = header.execution_info.unwrap();
        assert_eq!(execution.title_id, 0x5A5A_07D1);
        assert_eq!(execution.version.to_string(), "1.2.3456.78");
        assert_eq!(execution.disc_count, 1);
        assert_eq!(header.file_format.encryption, Encryption::None);
        assert_eq!(header.file_format.compression, Compression::None);
    }

    #[test]
    fn image_base_optional_header_wins_over_security_info() {
        let mut builder = XexBuilder::new(vec![0; 0x1_0000]);
        builder.image_base_override = Some(0x8300_0000);
        let header = Header::parse(&builder.build().bytes).unwrap();
        assert_eq!(header.security.load_address, 0x8200_0000);
        assert_eq!(header.base_address(), 0x8300_0000);
    }

    #[test]
    fn page_size_follows_the_image_flag() {
        let mut builder = XexBuilder::new(vec![0; 0x2000]);
        builder.page_size = 0x1000;
        let header = Header::parse(&builder.build().bytes).unwrap();
        assert_eq!(header.security.page_size(), 0x1000);
        assert_eq!(header.security.page_descriptors[0].page_count(), 2);
        assert!(
            header
                .security
                .image_flags
                .names()
                .contains(&"page_size_4kb")
        );
    }

    #[test]
    fn optional_data_resolves_inline_and_offset_values() {
        let file = sample();
        let header = Header::parse(&file).unwrap();
        let (_, inline) = header
            .optional_data(&file, key::ENTRY_POINT)
            .unwrap()
            .unwrap();
        assert_eq!(inline, 0x8201_0000u32.to_be_bytes());
        let (_, tls) = header.optional_data(&file, key::TLS_INFO).unwrap().unwrap();
        assert_eq!(tls.len(), 16);
        assert_eq!(header.optional_data(&file, 0x1234_56FF).unwrap(), None);
    }

    #[test]
    fn parses_the_resource_table() {
        let mut data = 36u32.to_be_bytes().to_vec();
        for (name, address, size) in [
            (b"AAAAAAAA", 0x8210_0000u32, 0x10u32),
            (b"B\0\0\0\0\0\0\0", 0x8210_0100, 0x20),
        ] {
            data.extend_from_slice(name);
            data.extend_from_slice(&address.to_be_bytes());
            data.extend_from_slice(&size.to_be_bytes());
        }
        let mut builder = XexBuilder::new(vec![0; 0x1_0000]);
        builder.extra_optional.push((key::RESOURCE_INFO, data));
        let header = Header::parse(&builder.build().bytes).unwrap();
        assert_eq!(header.resources.len(), 2);
        assert_eq!(header.resources[0].name, "AAAAAAAA");
        assert_eq!(header.resources[1].name, "B");
        assert_eq!(header.resources[1].address, 0x8210_0100);
        assert_eq!(header.resources[1].size, 0x20);
    }

    #[test]
    fn knows_the_names_of_optional_headers() {
        assert_eq!(key_name(key::ENTRY_POINT), Some("entry_point"));
        assert_eq!(key_name(0x0004_0310), Some("game_ratings"));
        assert_eq!(key_name(0x1234_5678), None);
    }

    #[test]
    fn rejects_a_bad_magic_with_offset_and_field() {
        let mut file = sample();
        file[0..4].copy_from_slice(b"XEX1");
        let err = Header::parse(&file).unwrap_err();
        assert_eq!(err.location, Location::File(0));
        assert_eq!(err.field, "header.magic");
        assert_eq!(
            err.kind,
            ErrorKind::BadMagic {
                expected: XEX2_MAGIC,
                found: 0x5845_5831,
            }
        );
    }

    #[test]
    fn rejects_empty_and_truncated_files() {
        let err = Header::parse(&[]).unwrap_err();
        assert_eq!(err.location, Location::File(0));
        assert_eq!(err.field, "header.magic");

        let file = sample();
        let err = Header::parse(&file[..4]).unwrap_err();
        assert_eq!(err.field, "header.module_flags");
        assert_eq!(err.location, Location::File(4));
    }

    #[test]
    fn rejects_patches_as_out_of_scope() {
        for flag in [0x10, 0x20, 0x40] {
            let mut file = sample();
            be32(&mut file, 4, flag);
            let err = Header::parse(&file).unwrap_err();
            assert_eq!(err.location, Location::File(4));
            assert_eq!(err.field, "header.module_flags");
            assert!(matches!(err.kind, ErrorKind::Unsupported { .. }));
        }
    }

    #[test]
    fn rejects_a_header_size_outside_the_file() {
        let mut file = sample();
        be32(&mut file, 8, 0x10);
        let err = Header::parse(&file).unwrap_err();
        assert_eq!(err.location, Location::File(8));
        assert!(matches!(err.kind, ErrorKind::InvalidValue { .. }));

        let mut file = sample();
        be32(&mut file, 8, u32::MAX);
        let err = Header::parse(&file).unwrap_err();
        assert_eq!(err.field, "header.header_size");
        assert!(matches!(err.kind, ErrorKind::Truncated { .. }));
    }

    #[test]
    fn rejects_a_directory_larger_than_the_headers() {
        let mut file = sample();
        be32(&mut file, 0x14, u32::MAX);
        let err = Header::parse(&file).unwrap_err();
        assert_eq!(err.location, Location::File(0x18));
        assert_eq!(err.field, "header.optional_headers");
    }

    #[test]
    fn rejects_a_security_info_outside_the_headers() {
        let mut file = sample();
        be32(&mut file, 0x10, u32::MAX);
        let err = Header::parse(&file).unwrap_err();
        assert_eq!(err.location, Location::File(u64::from(u32::MAX)));
        assert_eq!(err.field, "security_info");
    }

    #[test]
    fn rejects_bad_security_info_fields() {
        let built = XexBuilder::new(vec![0; 0x1_0000]).build();
        let base = built.security_offset as usize;

        for (field_offset, value, field) in [
            (0x0usize, 0x10u32, "security_info.info_size"),
            (0x4, 0, "security_info.image_size"),
            (0x4, MAX_IMAGE_SIZE + 1, "security_info.image_size"),
            (0x180, u32::MAX, "security_info.page_descriptors"),
        ] {
            let mut file = built.bytes.clone();
            be32(&mut file, base + field_offset, value);
            let err = Header::parse(&file).unwrap_err();
            assert_eq!(err.field, field);
        }
    }

    #[test]
    fn requires_the_file_format_info() {
        let mut built = XexBuilder::new(vec![0; 0x1_0000]).build();
        let offset = built.optional_entry_offset(key::FILE_FORMAT_INFO);
        be32(&mut built.bytes, offset, 0x0BAD_0000);
        let err = Header::parse(&built.bytes).unwrap_err();
        assert_eq!(err.field, "optional.file_format_info");
        assert_eq!(err.kind, ErrorKind::Missing);
    }

    #[test]
    fn rejects_an_optional_header_pointing_outside_the_headers() {
        let mut built = XexBuilder::new(vec![0; 0x1_0000]).build();
        let offset = built.optional_entry_offset(key::TLS_INFO);
        be32(&mut built.bytes, offset + 4, u32::MAX - 4);
        let err = Header::parse(&built.bytes).unwrap_err();
        assert_eq!(err.field, "optional.tls_info");
        assert_eq!(err.location, Location::File(u64::from(u32::MAX) - 4));
    }

    #[test]
    fn rejects_a_size_prefix_too_small_for_itself() {
        let mut built = XexBuilder::new(vec![0; 0x1_0000]).build();
        let offset = built.optional_data_offset(key::ORIGINAL_PE_NAME);
        be32(&mut built.bytes, offset, 2);
        let err = Header::parse(&built.bytes).unwrap_err();
        assert_eq!(err.field, "optional.original_pe_name");
        assert_eq!(err.location, Location::File(offset as u64));
    }

    #[test]
    fn rejects_unknown_encryption_and_compression_types() {
        let built = XexBuilder::new(vec![0; 0x1_0000]).build();
        let base = built.optional_data_offset(key::FILE_FORMAT_INFO);

        let mut file = built.bytes.clone();
        file[base + 4..base + 6].copy_from_slice(&7u16.to_be_bytes());
        let err = Header::parse(&file).unwrap_err();
        assert_eq!(err.field, "file_format_info.encryption_type");
        assert_eq!(err.location, Location::File(base as u64 + 4));

        let mut file = built.bytes.clone();
        file[base + 6..base + 8].copy_from_slice(&9u16.to_be_bytes());
        let err = Header::parse(&file).unwrap_err();
        assert_eq!(err.field, "file_format_info.compression_type");
        assert_eq!(err.location, Location::File(base as u64 + 6));
    }

    #[test]
    fn rejects_lzx_windows_the_format_does_not_allow() {
        let mut builder = XexBuilder::new(vec![0; 0x1_0000]);
        builder.compression = FixtureCompression::LzxUncompressedBlocks;
        let built = builder.build();
        let base = built.optional_data_offset(key::FILE_FORMAT_INFO);
        for window in [0, 0x4000, 0x8001, 0x400_0000] {
            let mut file = built.bytes.clone();
            be32(&mut file, base + 8, window);
            let err = Header::parse(&file).unwrap_err();
            assert_eq!(err.field, "file_format_info.window_size");
            assert_eq!(err.location, Location::File(base as u64 + 8));
        }
    }

    #[test]
    fn rejects_delta_compression_as_out_of_scope() {
        let built = XexBuilder::new(vec![0; 0x1_0000]).build();
        let base = built.optional_data_offset(key::FILE_FORMAT_INFO);
        let mut file = built.bytes;
        file[base + 6..base + 8].copy_from_slice(&3u16.to_be_bytes());
        let err = Header::parse(&file).unwrap_err();
        assert!(matches!(err.kind, ErrorKind::Unsupported { value: 3, .. }));
    }

    #[test]
    fn error_messages_name_offset_and_field() {
        let mut file = sample();
        file[0] = b'Y';
        let message = Header::parse(&file).unwrap_err().to_string();
        assert!(message.contains("file offset 0x0"), "{message}");
        assert!(message.contains("header.magic"), "{message}");
    }
}
