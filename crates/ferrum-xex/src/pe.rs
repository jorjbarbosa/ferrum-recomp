// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The PE headers inside a XEX image, and the tables they point to.
//!
//! The XEX image is laid out as it will be in memory, so sections are found by their virtual
//! address and never by their raw file pointer. PE headers are little-endian as in any PE, while
//! the tables the guest itself reads, such as `.pdata`, are big-endian. Validation follows
//! `XexModule::ReadPEHeaders` in `src/xenia/cpu/xex_module.cc` in Xenia.
//!
//! The section table describes what the linker produced, which is not always what the image holds.
//! The XEX builder drops sections like `.edata` and `.reloc`, so these can point past the end of
//! the image or at unrelated data, such as resources placed where they used to be. They are listed
//! as declared, and nothing else in this module relies on them.

use crate::error::{ErrorKind, Result};
use crate::reader::Reader;

/// `MZ`.
const DOS_MAGIC: u16 = 0x5A4D;
/// `PE\0\0`.
const NT_MAGIC: u32 = 0x0000_4550;
/// `IMAGE_FILE_MACHINE_POWERPCBE`.
const MACHINE_POWERPC_BE: u16 = 0x01F2;
/// `IMAGE_FILE_32BIT_MACHINE`.
const CHARACTERISTIC_32BIT: u16 = 0x0100;
/// Size of the optional header of a 32-bit PE, the only size Xbox 360 images use.
const OPTIONAL_HEADER_SIZE: u16 = 0xE0;
/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`.
const OPTIONAL_MAGIC: u16 = 0x010B;
/// `IMAGE_SUBSYSTEM_XBOX`.
const SUBSYSTEM_XBOX: u16 = 14;
/// Offset of the file header from the NT signature.
const FILE_HEADER_OFFSET: u64 = 4;
/// Offset of the optional header from the NT signature.
const OPTIONAL_HEADER_OFFSET: u64 = 0x18;
/// Offset of the data directories from the start of the optional header.
const DATA_DIRECTORIES_OFFSET: u64 = 0x60;
/// Maximum number of data directories in the optional header.
const MAX_DATA_DIRECTORIES: u32 = 16;
/// Size of one section header.
const SECTION_HEADER_SIZE: u64 = 40;
/// Index of the exception directory, which locates `.pdata`.
const EXCEPTION_DIRECTORY: usize = 3;
/// Size of one `.pdata` entry.
const RUNTIME_FUNCTION_SIZE: usize = 8;

/// `IMAGE_SCN_CNT_CODE`.
const SECTION_CODE: u32 = 0x0000_0020;
/// `IMAGE_SCN_MEM_EXECUTE`.
const SECTION_EXECUTE: u32 = 0x2000_0000;
/// `IMAGE_SCN_MEM_READ`.
const SECTION_READ: u32 = 0x4000_0000;
/// `IMAGE_SCN_MEM_WRITE`.
const SECTION_WRITE: u32 = 0x8000_0000;

/// An entry of the PE data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    /// Offset of the data from the image base.
    pub rva: u32,
    /// Size of the data.
    pub size: u32,
}

/// The fields of the PE headers that matter for recompilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeHeaders {
    /// Link time, in seconds since the Unix epoch.
    pub time_date_stamp: u32,
    /// Base address the linker chose.
    pub image_base: u32,
    /// Offset of the entry point from the image base.
    pub entry_rva: u32,
    /// Image size according to the linker, which can differ from the size of the XEX image.
    pub size_of_image: u32,
    /// The data directories.
    pub data_directories: Vec<DataDirectory>,
}

/// A section, as declared by the PE section table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Section name.
    pub name: String,
    /// Guest address.
    pub address: u32,
    /// Size in memory.
    pub virtual_size: u32,
    /// Offset in the original PE file. Not meaningful in a XEX image.
    pub raw_pointer: u32,
    /// Size in the original PE file.
    pub raw_size: u32,
    /// The `IMAGE_SCN_*` flags.
    pub characteristics: u32,
}

impl Section {
    /// Returns the address just past the end of the section, which can reach the 33rd bit.
    pub fn end(&self) -> u64 {
        u64::from(self.address) + u64::from(self.virtual_size)
    }

    /// Returns whether the section is marked as holding code.
    pub fn is_code(&self) -> bool {
        self.characteristics & SECTION_CODE != 0
    }

    /// Returns whether the guest can read the section.
    pub fn is_readable(&self) -> bool {
        self.characteristics & SECTION_READ != 0
    }

    /// Returns whether the guest can write to the section.
    pub fn is_writable(&self) -> bool {
        self.characteristics & SECTION_WRITE != 0
    }

    /// Returns whether the guest can execute the section.
    pub fn is_executable(&self) -> bool {
        self.characteristics & SECTION_EXECUTE != 0
    }

    /// Returns whether a guest address lies in the section.
    pub fn contains(&self, address: u32) -> bool {
        address >= self.address && u64::from(address) < self.end()
    }
}

/// An entry of `.pdata`: an `IMAGE_CE_RUNTIME_FUNCTION_ENTRY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    /// Guest address of the function.
    pub begin: u32,
    /// The packed second word: `exception:1 is_32bit:1 length:22 prolog:8`, high bit first.
    pub raw: u32,
}

impl RuntimeFunction {
    /// Returns the length of the prolog, in instructions.
    pub fn prolog_words(self) -> u32 {
        self.raw & 0xFF
    }

    /// Returns the length of the function, in instructions.
    pub fn length_words(self) -> u32 {
        (self.raw >> 8) & 0x3F_FFFF
    }

    /// Returns the length of the function, in bytes.
    pub fn size(self) -> u32 {
        // A 22-bit count of 4-byte words needs 24 bits.
        self.length_words() * 4
    }

    /// Returns the address just past the end of the function, which can reach the 33rd bit.
    pub fn end(self) -> u64 {
        u64::from(self.begin) + u64::from(self.size())
    }

    /// Returns whether the function holds 32-bit instructions.
    pub fn is_32bit(self) -> bool {
        self.raw & 0x4000_0000 != 0
    }

    /// Returns whether the function has an exception handler.
    pub fn has_exception_handler(self) -> bool {
        self.raw & 0x8000_0000 != 0
    }
}

/// What the PE headers of an image describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pe {
    pub(crate) headers: PeHeaders,
    pub(crate) sections: Vec<Section>,
    pub(crate) pdata: Vec<RuntimeFunction>,
}

/// Parses the PE headers of a XEX image that loads at `base`.
pub(crate) fn parse(image: &[u8], base: u32) -> Result<Pe> {
    let reader = Reader::image(image);
    let nt = read_dos_header(&reader)?;
    check_nt_headers(&reader, nt)?;
    let optional = nt + OPTIONAL_HEADER_OFFSET;
    let headers = read_optional_header(&reader, nt)?;
    let section_count = reader.le_u16(nt + FILE_HEADER_OFFSET + 2, "pe.file.number_of_sections")?;
    let sections = read_sections(
        &reader,
        optional + u64::from(OPTIONAL_HEADER_SIZE),
        section_count,
        base,
    )?;
    let pdata = read_pdata(&reader, &headers, &sections, base)?;
    Ok(Pe {
        headers,
        sections,
        pdata,
    })
}

/// Checks the DOS header and returns the offset of the NT headers.
fn read_dos_header(reader: &Reader<'_>) -> Result<u64> {
    let magic = reader.le_u16(0, "pe.dos.magic")?;
    if magic != DOS_MAGIC {
        let kind = ErrorKind::BadMagic {
            expected: DOS_MAGIC.into(),
            found: magic.into(),
        };
        return Err(reader.error(0, "pe.dos.magic", kind));
    }
    reader.le_u32(0x3C, "pe.dos.e_lfanew").map(u64::from)
}

/// Checks that the NT headers describe a 32-bit big-endian PowerPC Xbox image.
fn check_nt_headers(reader: &Reader<'_>, nt: u64) -> Result<()> {
    let signature = reader.le_u32(nt, "pe.nt.signature")?;
    if signature != NT_MAGIC {
        let kind = ErrorKind::BadMagic {
            expected: NT_MAGIC,
            found: signature,
        };
        return Err(reader.error(nt, "pe.nt.signature", kind));
    }
    let file = nt + FILE_HEADER_OFFSET;
    let optional = nt + OPTIONAL_HEADER_OFFSET;
    let checks = [
        (
            file,
            "pe.file.machine",
            MACHINE_POWERPC_BE,
            "not big-endian PowerPC",
        ),
        (
            file + 0x10,
            "pe.file.size_of_optional_header",
            OPTIONAL_HEADER_SIZE,
            "not the size of a 32-bit optional header",
        ),
        (
            optional,
            "pe.optional.magic",
            OPTIONAL_MAGIC,
            "not a 32-bit optional header",
        ),
        (
            optional + 0x44,
            "pe.optional.subsystem",
            SUBSYSTEM_XBOX,
            "not the Xbox subsystem",
        ),
    ];
    for (offset, field, expected, reason) in checks {
        let value = reader.le_u16(offset, field)?;
        if value != expected {
            let value = value.into();
            return Err(reader.error(offset, field, ErrorKind::Unsupported { value, reason }));
        }
    }
    let characteristics = reader.le_u16(file + 0x12, "pe.file.characteristics")?;
    if characteristics & CHARACTERISTIC_32BIT == 0 {
        let kind = ErrorKind::Unsupported {
            value: characteristics.into(),
            reason: "not marked as a 32-bit image",
        };
        return Err(reader.error(file + 0x12, "pe.file.characteristics", kind));
    }
    Ok(())
}

/// Reads the optional header fields of the NT headers at `nt`.
fn read_optional_header(reader: &Reader<'_>, nt: u64) -> Result<PeHeaders> {
    let optional = nt + OPTIONAL_HEADER_OFFSET;
    let count_field = "pe.optional.number_of_rva_and_sizes";
    let count = reader
        .le_u32(optional + 0x5C, count_field)?
        .min(MAX_DATA_DIRECTORIES);
    let data_directories = (0..u64::from(count))
        .map(|index| {
            let offset = optional + DATA_DIRECTORIES_OFFSET + index * 8;
            Ok(DataDirectory {
                rva: reader.le_u32(offset, "pe.optional.data_directory.rva")?,
                size: reader.le_u32(offset + 4, "pe.optional.data_directory.size")?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(PeHeaders {
        time_date_stamp: reader.le_u32(nt + 8, "pe.file.time_date_stamp")?,
        image_base: reader.le_u32(optional + 0x1C, "pe.optional.image_base")?,
        entry_rva: reader.le_u32(optional + 0x10, "pe.optional.address_of_entry_point")?,
        size_of_image: reader.le_u32(optional + 0x38, "pe.optional.size_of_image")?,
        data_directories,
    })
}

/// Reads the section table.
fn read_sections(reader: &Reader<'_>, table: u64, count: u16, base: u32) -> Result<Vec<Section>> {
    (0..u64::from(count))
        .map(|index| {
            let offset = table + index * SECTION_HEADER_SIZE;
            let field = |name: &str| format!("pe.sections[{index}].{name}");
            let name: [u8; 8] = reader.array(offset, field("name"))?;
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            let rva = reader.le_u32(offset + 12, field("virtual_address"))?;
            Ok(Section {
                name: String::from_utf8_lossy(&name[..end]).into_owned(),
                address: base.wrapping_add(rva),
                virtual_size: reader.le_u32(offset + 8, field("virtual_size"))?,
                raw_size: reader.le_u32(offset + 16, field("size_of_raw_data"))?,
                raw_pointer: reader.le_u32(offset + 20, field("pointer_to_raw_data"))?,
                characteristics: reader.le_u32(offset + 36, field("characteristics"))?,
            })
        })
        .collect()
}

/// Reads `.pdata`. The exception directory is the authority on where it is; the section named
/// `.pdata` is the fallback for images whose directory is empty. Zero entries are padding.
fn read_pdata(
    reader: &Reader<'_>,
    headers: &PeHeaders,
    sections: &[Section],
    base: u32,
) -> Result<Vec<RuntimeFunction>> {
    let directory = headers
        .data_directories
        .get(EXCEPTION_DIRECTORY)
        .filter(|directory| directory.size != 0)
        .copied();
    let section = || {
        let section = sections.iter().find(|section| section.name == ".pdata")?;
        Some(DataDirectory {
            rva: section.address.wrapping_sub(base),
            size: section.virtual_size,
        })
    };
    let Some(location) = directory.or_else(section) else {
        return Ok(Vec::new());
    };
    let table = reader.bytes(
        location.rva.into(),
        location.size.into(),
        "pe.exception_directory",
    )?;
    Ok(table
        .as_chunks::<RUNTIME_FUNCTION_SIZE>()
        .0
        .iter()
        .map(|entry| RuntimeFunction {
            begin: u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]),
            raw: u32::from_be_bytes([entry[4], entry[5], entry[6], entry[7]]),
        })
        .filter(|function| function.begin != 0)
        .collect())
}
