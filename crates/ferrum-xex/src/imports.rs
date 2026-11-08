// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The import libraries of a module.
//!
//! The file header lists, per library, the guest addresses of import records inside the image. A
//! record holds a type and an ordinal, and there are two types. A slot, of type 0, is a word the
//! loader overwrites with an address. A thunk, of type 1, is a stub the loader makes callable.
//!
//! Records do not map one to one onto imports: every import has a slot, and a function has a thunk
//! as well. So a type-0 record does not by itself mean "variable", and records have to be paired by
//! ordinal, since nothing guarantees their order. Follows `XexModule::SetupLibraryImports` in
//! `src/xenia/cpu/xex_module.cc` in Xenia, which also takes an import's kind from the table.

use std::collections::BTreeMap;

use crate::error::{ErrorKind, Result};
use crate::header::{Header, Version, key};
use crate::image::Warning;
use crate::ordinals::{ImportKind, KnownLibrary};
use crate::reader::Reader;

/// Offset of the library name strings in the import libraries header.
const STRINGS_OFFSET: u64 = 12;
/// Size of a library entry, up to its list of records.
const LIBRARY_FIXED_SIZE: u64 = 0x28;
/// Record type of a slot.
const RECORD_SLOT: u32 = 0;
/// Record type of a thunk.
const RECORD_THUNK: u32 = 1;

/// A library the module imports from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportLibrary {
    /// File name of the library, such as `xboxkrnl.exe`.
    pub name: String,
    /// Library id.
    pub id: u32,
    /// Version the module was built against.
    pub version: Version,
    /// Oldest version the module accepts.
    pub min_version: Version,
    /// The imports, sorted by ordinal.
    pub imports: Vec<Import>,
}

/// A function or variable the module imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Import {
    /// Ordinal of the export in its library.
    pub ordinal: u16,
    /// Name of the export, if the library and the ordinal are in the tables.
    pub name: Option<&'static str>,
    /// Whether the import is a function or a variable.
    pub kind: ImportKind,
    /// Guest address of the word the loader fills in.
    pub slot: Option<u32>,
    /// Guest address of the stub that calls the function.
    pub thunk: Option<u32>,
}

/// Records of one ordinal, while they are being paired.
#[derive(Default)]
struct Paired {
    slot: Option<u32>,
    thunk: Option<u32>,
}

/// Reads the import libraries of a module, if it has any.
pub(crate) fn read_imports(
    file: &[u8],
    image: &[u8],
    header: &Header,
    warnings: &mut Vec<Warning>,
) -> Result<Vec<ImportLibrary>> {
    let Some((base, data)) = header.optional_data(file, key::IMPORT_LIBRARIES)? else {
        return Ok(Vec::new());
    };
    // From here on nothing may read past the end of the table.
    let end = base + data.len() as u64;
    let table = Reader::file(
        file.get(..usize::try_from(end).unwrap_or(usize::MAX))
            .unwrap_or(file),
    );
    let names = read_names(&table, base)?;
    let strings_size = u64::from(table.be_u32(base + 4, "import_libraries.string_table_size")?);

    let mut libraries = Vec::new();
    let mut cursor = base + STRINGS_OFFSET + strings_size;
    while cursor < end {
        let index = libraries.len();
        let size = u64::from(table.be_u32(cursor, library_field(index, "size"))?);
        if size == 0 {
            break;
        }
        let context = LibraryContext {
            table: &table,
            image: Reader::image(image),
            base: header.base_address(),
            offset: cursor,
            size,
            index,
        };
        libraries.push(context.read(&names, warnings)?);
        cursor += size;
    }
    Ok(libraries)
}

/// Builds the field name of a library entry.
fn library_field(index: usize, name: &str) -> String {
    format!("import_libraries[{index}].{name}")
}

/// Reads the name strings, each NUL-terminated and padded to 4 bytes.
fn read_names(table: &Reader<'_>, base: u64) -> Result<Vec<String>> {
    let size = u64::from(table.be_u32(base + 4, "import_libraries.string_table_size")?);
    let count = table.be_u32(base + 8, "import_libraries.string_count")?;
    let strings = table.bytes(base + STRINGS_OFFSET, size, "import_libraries.strings")?;
    let mut names = Vec::new();
    let mut position = 0;
    while position < strings.len() && (names.len() as u64) < u64::from(count) {
        let rest = &strings[position..];
        let length = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        names.push(String::from_utf8_lossy(&rest[..length]).into_owned());
        position = (position + length + 1).next_multiple_of(4);
    }
    Ok(names)
}

/// What reading one library entry needs to know.
struct LibraryContext<'a> {
    table: &'a Reader<'a>,
    image: Reader<'a>,
    base: u32,
    offset: u64,
    size: u64,
    index: usize,
}

impl LibraryContext<'_> {
    /// Reads the library entry.
    fn read(&self, names: &[String], warnings: &mut Vec<Warning>) -> Result<ImportLibrary> {
        if self.size < LIBRARY_FIXED_SIZE {
            let kind = ErrorKind::InvalidValue {
                value: self.size,
                reason: "smaller than the fixed part of a library entry",
            };
            return Err(self.error(self.offset, "size", kind));
        }
        let name = self.read_name(names)?;
        let known = KnownLibrary::from_file_name(&name);
        if known.is_none() {
            warnings.push(Warning::UnknownImportLibrary {
                library: name.clone(),
            });
        }
        let paired = self.read_records(&name, warnings)?;
        let imports = paired
            .into_iter()
            .map(|(ordinal, records)| resolve(&name, known, ordinal, &records, warnings))
            .collect();
        Ok(ImportLibrary {
            id: self.u32_field(0x18, "id")?,
            version: Version(self.u32_field(0x1C, "version")?),
            min_version: Version(self.u32_field(0x20, "min_version")?),
            name,
            imports,
        })
    }

    fn u32_field(&self, offset: u64, name: &str) -> Result<u32> {
        self.table
            .be_u32(self.offset + offset, library_field(self.index, name))
    }

    fn error(&self, offset: u64, name: &str, kind: ErrorKind) -> crate::Error {
        self.table
            .error(offset, library_field(self.index, name), kind)
    }

    /// Finds the library's file name. As in Xenia, only the low byte of the index counts.
    fn read_name(&self, names: &[String]) -> Result<String> {
        let offset = self.offset + 0x24;
        let raw = self
            .table
            .be_u16(offset, library_field(self.index, "name_index"))?;
        names.get(usize::from(raw & 0xFF)).cloned().ok_or_else(|| {
            let kind = ErrorKind::InvalidValue {
                value: raw.into(),
                reason: "no such entry in the string table",
            };
            self.error(offset, "name_index", kind)
        })
    }

    /// Reads the import records of the entry, pairing them by ordinal.
    fn read_records(
        &self,
        library: &str,
        warnings: &mut Vec<Warning>,
    ) -> Result<BTreeMap<u16, Paired>> {
        let count_offset = self.offset + 0x26;
        let count_field = library_field(self.index, "record_count");
        let count = u64::from(self.table.be_u16(count_offset, count_field)?);
        if LIBRARY_FIXED_SIZE + count * 4 > self.size {
            let kind = ErrorKind::InvalidValue {
                value: count,
                reason: "more records than fit in the library entry",
            };
            return Err(self.error(count_offset, "record_count", kind));
        }
        let mut paired: BTreeMap<u16, Paired> = BTreeMap::new();
        for record in 0..count {
            let name = format!("records[{record}]");
            let address = self.u32_field(LIBRARY_FIXED_SIZE + record * 4, &name)?;
            // Xenia skips these too.
            if address == 0 {
                continue;
            }
            let field = library_field(self.index, &name);
            let rva = u64::from(address.wrapping_sub(self.base));
            let value = self.image.be_u32(rva, field.clone())?;
            // The mask keeps 16 bits, so the truncation loses nothing.
            let ordinal = (value & 0xFFFF) as u16;
            let entry = paired.entry(ordinal).or_default();
            let target = match value >> 24 {
                RECORD_SLOT => &mut entry.slot,
                RECORD_THUNK => &mut entry.thunk,
                other => {
                    let kind = ErrorKind::InvalidValue {
                        value: other.into(),
                        reason: "an import record is either a slot or a thunk",
                    };
                    return Err(self.image.error(rva, field, kind));
                }
            };
            if target.replace(address).is_some() {
                warnings.push(Warning::DuplicateImportRecord {
                    library: library.to_owned(),
                    ordinal,
                });
            }
        }
        Ok(paired)
    }
}

/// Turns the records of an ordinal into an import, naming it from the tables.
///
/// The table decides the kind, as it does in Xenia. Without a table entry the only evidence left is
/// whether the module asked for a thunk.
fn resolve(
    library: &str,
    known: Option<KnownLibrary>,
    ordinal: u16,
    records: &Paired,
    warnings: &mut Vec<Warning>,
) -> Import {
    let entry = known.and_then(|known| known.lookup(ordinal));
    let inferred = if records.thunk.is_some() {
        ImportKind::Function
    } else {
        ImportKind::Variable
    };
    if let Some(entry) = entry {
        if entry.kind != inferred {
            warnings.push(Warning::ImportKindMismatch {
                library: library.to_owned(),
                ordinal,
                name: entry.name,
                kind: entry.kind,
            });
        }
    } else if known.is_some() {
        warnings.push(Warning::UnknownImportOrdinal {
            library: library.to_owned(),
            ordinal,
        });
    }
    Import {
        ordinal,
        name: entry.map(|entry| entry.name),
        kind: entry.map_or(inferred, |entry| entry.kind),
        slot: records.slot,
        thunk: records.thunk,
    }
}
