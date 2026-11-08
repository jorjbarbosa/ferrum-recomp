// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! A complete synthetic module: PE headers, sections, `.pdata`, exports and imports.
//!
//! Its shape copies what real images do, including the parts that trip naive parsers: raw file
//! pointers that differ from virtual addresses, a section that lies past the end of the image, an
//! export data directory that points at nothing useful, and a zero entry at the end of `.pdata`.

use super::{FixtureCompression, FixtureEncryption, PageRun, XexBuilder, be32};
use crate::header::key;

/// Writes a little-endian `u32` over the four bytes at `offset`.
fn le32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Writes a little-endian `u16` over the two bytes at `offset`.
fn le16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// File offset of the NT headers within the image.
pub const NT_OFFSET: usize = 0x80;
/// Offset from the image base of `.rdata`.
pub const RDATA_RVA: u32 = 0x400;
/// Offset from the image base of `.pdata`.
pub const PDATA_RVA: u32 = 0xA00;
/// Size of the `.pdata` table: three functions and a zero entry.
pub const PDATA_SIZE: u32 = 0x20;
/// The characteristics of `.rdata`: initialized data, readable.
pub const RDATA_FLAGS: u32 = 0x4000_0040;
/// The characteristics of `.text`: code, readable and executable.
pub const TEXT_FLAGS: u32 = 0x6000_0020;
/// The characteristics of `.data`: initialized data, readable and writable.
pub const DATA_FLAGS: u32 = 0xC000_0040;
/// The characteristics of `.reloc`: initialized data, readable and discardable.
pub const RELOC_FLAGS: u32 = 0x4200_0040;

/// Size of the fixed part of the optional header up to the data directories.
const DATA_DIRECTORIES: usize = NT_OFFSET + 0x18 + 0x60;
/// File offset of the section table: right after the optional header.
pub const SECTION_TABLE: usize = NT_OFFSET + 0x18 + 0xE0;

/// Offset from `.data` of the first import slot.
pub const SLOTS_OFFSET: u32 = 0x100;
/// Offset from `.text` of the first import thunk.
pub const THUNKS_OFFSET: u32 = 0x400;
/// Size of one import thunk: the record, a reserved word, `mtctr r11` and `bctr`.
pub const THUNK_SIZE: u32 = 16;

/// An import of a [`LibrarySpec`].
#[derive(Debug, Clone, Copy)]
pub struct ImportSpec {
    /// The ordinal.
    pub ordinal: u16,
    /// Whether the import has a thunk, which is what makes it a function.
    pub thunk: bool,
}

/// An import library of a sample module.
#[derive(Debug, Clone)]
pub struct LibrarySpec {
    /// File name of the library.
    pub name: &'static str,
    /// The imports.
    pub imports: Vec<ImportSpec>,
}

/// The import libraries of the default sample. The libraries are not in the order of the name
/// table, to catch parsers that pair them by position.
pub fn default_libraries() -> Vec<LibrarySpec> {
    let function = |ordinal| ImportSpec {
        ordinal,
        thunk: true,
    };
    let variable = |ordinal| ImportSpec {
        ordinal,
        thunk: false,
    };
    vec![
        LibrarySpec {
            name: "xboxkrnl.exe",
            // ExCreateThread, XboxHardwareInfo, KeDebugMonitorData.
            imports: vec![function(0x000D), variable(0x0156), variable(0x0059)],
        },
        LibrarySpec {
            name: "xam.xex",
            // XamInputGetState, XamShowMessageBoxUI.
            imports: vec![function(0x0191), function(0x02CA)],
        },
    ]
}

/// A section of the sample image: name, offset from the base, size, raw pointer and flags.
struct SampleSection {
    name: &'static [u8],
    rva: u32,
    size: u32,
    raw: u32,
    flags: u32,
}

/// Describes a sample module; every offset that depends on the page size is scaled by it.
#[derive(Debug, Clone, Copy)]
pub struct SampleLayout {
    /// Guest address of the image.
    pub base: u32,
    /// Size of one page; also the distance between the sections that start on a page.
    pub page_size: u32,
}

impl Default for SampleLayout {
    /// A module with 64 KiB pages at the usual title address.
    fn default() -> Self {
        Self {
            base: 0x8200_0000,
            page_size: 0x1_0000,
        }
    }
}

impl SampleLayout {
    /// A module small enough to be parsed thousands of times by a mutation test.
    pub fn tiny() -> Self {
        Self {
            base: 0x9200_0000,
            page_size: 0x1000,
        }
    }

    /// Returns the guest address of `.text`.
    pub fn text(self) -> u32 {
        self.base + self.page_size
    }

    /// Returns the size of the image: read-only data, code and two pages of writable data.
    pub fn image_size(self) -> u32 {
        4 * self.page_size
    }

    /// Returns the sections of the image.
    fn sections(self) -> [SampleSection; 5] {
        let unit = self.page_size;
        [
            SampleSection {
                name: b".rdata",
                rva: RDATA_RVA,
                size: 0x500,
                raw: 0x400,
                flags: RDATA_FLAGS,
            },
            SampleSection {
                name: b".pdata",
                rva: PDATA_RVA,
                size: PDATA_SIZE,
                raw: 0xA00,
                flags: RDATA_FLAGS,
            },
            SampleSection {
                name: b".text",
                rva: unit,
                size: 0x800,
                raw: 0xC00,
                flags: TEXT_FLAGS,
            },
            SampleSection {
                name: b".data",
                rva: 2 * unit,
                size: 0x200,
                raw: 0x1400,
                flags: DATA_FLAGS,
            },
            SampleSection {
                name: b".reloc",
                rva: 4 * unit,
                size: 0x1000,
                raw: 0x1600,
                flags: RELOC_FLAGS,
            },
        ]
    }

    /// Writes the DOS and NT headers and the section table.
    fn write_headers(self, image: &mut [u8]) {
        image[0..2].copy_from_slice(b"MZ");
        le32(image, 0x3C, NT_OFFSET as u32);
        let nt = NT_OFFSET;
        image[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let sections = self.sections();
        le16(image, nt + 4, 0x01F2);
        le16(image, nt + 6, sections.len() as u16);
        le32(image, nt + 8, 0x5F5E_1000);
        le16(image, nt + 0x14, 0xE0);
        le16(image, nt + 0x16, 0x0102);
        let optional = nt + 0x18;
        le16(image, optional, 0x010B);
        le32(image, optional + 0x10, self.page_size);
        le32(image, optional + 0x1C, self.base);
        le32(image, optional + 0x38, 6 * self.page_size);
        le16(image, optional + 0x44, 14);
        le32(image, optional + 0x5C, 16);
        // The export directory the linker wrote is gone from the image, as in real modules.
        le32(image, DATA_DIRECTORIES, 5 * self.page_size);
        le32(image, DATA_DIRECTORIES + 4, 0x40);
        // The exception directory.
        le32(image, DATA_DIRECTORIES + 3 * 8, PDATA_RVA);
        le32(image, DATA_DIRECTORIES + 3 * 8 + 4, PDATA_SIZE);
        for (index, section) in sections.iter().enumerate() {
            let at = SECTION_TABLE + index * 40;
            image[at..at + section.name.len()].copy_from_slice(section.name);
            le32(image, at + 8, section.size);
            le32(image, at + 12, section.rva);
            le32(image, at + 16, section.size.next_multiple_of(0x200));
            le32(image, at + 20, section.raw);
            le32(image, at + 36, section.flags);
        }
    }

    /// Writes `.pdata`: three functions, then a zero entry.
    fn write_pdata(self, image: &mut [u8]) {
        let text = self.text();
        let entries = [
            (text, (4 << 8) | 2 | 0x4000_0000u32),
            (text + 0x10, (8 << 8) | 3 | 0xC000_0000),
            (text + 0x30, 4 << 8),
        ];
        for (index, (begin, raw)) in entries.into_iter().enumerate() {
            let at = PDATA_RVA as usize + index * 8;
            be32(image, at, begin);
            be32(image, at + 4, raw);
        }
    }

    /// Writes the XEX export table at the start of `.rdata`, with ordinals 1 and 3 assigned.
    fn write_export_table(self, image: &mut [u8]) {
        let at = RDATA_RVA as usize;
        be32(image, at, 0x4800_0000);
        be32(image, at + 4, 0x0048_5645);
        be32(image, at + 8, 0x4800_0000);
        be32(image, at + 0x20, self.base >> 16);
        be32(image, at + 0x24, 3);
        be32(image, at + 0x28, 1);
        be32(image, at + 0x2C, self.page_size);
        be32(image, at + 0x30, 0);
        be32(image, at + 0x34, self.page_size + 0x10);
    }

    /// Generates the plain image.
    pub fn image(self) -> Vec<u8> {
        let mut image = vec![0; self.image_size() as usize];
        self.write_headers(&mut image);
        self.write_pdata(&mut image);
        self.write_export_table(&mut image);
        // Recognizable code and data, so that a mistake in decompression cannot go unnoticed.
        for (i, byte) in image[self.page_size as usize..][..0x800]
            .iter_mut()
            .enumerate()
        {
            *byte = (i % 251) as u8;
        }
        image[2 * self.page_size as usize..][..0x10].fill(0xDA);
        image
    }

    /// Writes the import records into `image` and returns the import libraries optional header.
    ///
    /// Each library lists a thunk before its slot, so a parser has to pair them by ordinal.
    pub fn write_imports(self, image: &mut [u8], libraries: &[LibrarySpec]) -> Vec<u8> {
        let mut names: Vec<&str> = libraries.iter().map(|library| library.name).collect();
        names.sort_unstable();
        names.dedup();

        let mut strings = Vec::new();
        for name in &names {
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            strings.resize(strings.len().next_multiple_of(4), 0);
        }

        let mut next_slot = 2 * self.page_size + SLOTS_OFFSET;
        let mut next_thunk = self.page_size + THUNKS_OFFSET;
        let mut entries = Vec::new();
        for library in libraries {
            let index = names.iter().position(|name| *name == library.name);
            let index = index.expect("every library name is in the table") as u32;
            let mut records = Vec::new();
            for import in &library.imports {
                let record = (index << 16) | u32::from(import.ordinal);
                if import.thunk {
                    let at = next_thunk as usize;
                    be32(image, at, (1 << 24) | record);
                    be32(image, at + 8, 0x7D69_03A6);
                    be32(image, at + 12, 0x4E80_0420);
                    records.push(self.base + next_thunk);
                    next_thunk += THUNK_SIZE;
                }
                be32(image, next_slot as usize, record);
                records.push(self.base + next_slot);
                next_slot += 4;
            }
            let mut entry = Vec::new();
            entry.extend_from_slice(&(0x28 + records.len() as u32 * 4).to_be_bytes());
            entry.extend_from_slice(&[0x11; 20]);
            entry.extend_from_slice(&0x1234_ABCDu32.to_be_bytes());
            entry.extend_from_slice(&0x2000_1882u32.to_be_bytes());
            entry.extend_from_slice(&0x2000_1686u32.to_be_bytes());
            entry.extend_from_slice(&(index as u16).to_be_bytes());
            entry.extend_from_slice(&(records.len() as u16).to_be_bytes());
            for record in records {
                entry.extend_from_slice(&record.to_be_bytes());
            }
            entries.extend_from_slice(&entry);
        }

        let mut table = Vec::new();
        let size = 12 + strings.len() + entries.len();
        table.extend_from_slice(&(size as u32).to_be_bytes());
        table.extend_from_slice(&(strings.len() as u32).to_be_bytes());
        table.extend_from_slice(&(names.len() as u32).to_be_bytes());
        table.extend_from_slice(&strings);
        table.extend_from_slice(&entries);
        table
    }

    /// Adds import libraries to a builder of this module.
    pub fn with_imports(self, builder: &mut XexBuilder, libraries: &[LibrarySpec]) {
        let table = self.write_imports(&mut builder.image, libraries);
        builder.import_table_count = libraries.len() as u32;
        builder
            .extra_optional
            .retain(|(key, _)| *key != key::IMPORT_LIBRARIES);
        builder.extra_optional.push((key::IMPORT_LIBRARIES, table));
    }

    /// Starts a builder for this module, with the default imports.
    pub fn builder(self) -> XexBuilder {
        let mut builder = XexBuilder::new(self.image());
        builder.load_address = self.base;
        builder.page_size = self.page_size;
        builder.entry_point = self.text();
        builder.export_table = self.base + RDATA_RVA;
        builder.page_runs = Some(vec![
            PageRun { kind: 3, pages: 1 },
            PageRun { kind: 1, pages: 1 },
            PageRun { kind: 2, pages: 2 },
        ]);
        builder.encryption = FixtureEncryption::None;
        builder.compression = FixtureCompression::None;
        self.with_imports(&mut builder, &default_libraries());
        builder
    }
}
