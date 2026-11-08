// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The exports of a module.
//!
//! There are two sources, read as in `XexModule::GetProcAddress` in
//! `src/xenia/cpu/xex_module.cc` in Xenia. The XEX export table, found through the security info,
//! maps ordinals to addresses. The PE export directory adds names, but only counts when the
//! `exports_by_name` optional header points to it: the data directory of the PE headers cannot be
//! trusted, because the XEX builder drops the section it refers to.

use std::collections::BTreeMap;

use crate::error::{ErrorKind, Result};
use crate::header::{Header, key};
use crate::reader::Reader;

/// The three words that open a XEX export table: two PowerPC `b .` and `\0HVE` between them.
const EXPORT_TABLE_MAGIC: [u32; 3] = [0x4800_0000, 0x0048_5645, 0x4800_0000];
/// Offset of the image base word in the XEX export table.
const IMAGE_BASE_OFFSET: u64 = 0x20;
/// Offset of the export count in the XEX export table.
const COUNT_OFFSET: u64 = 0x24;
/// Offset of the first ordinal in the XEX export table.
const BASE_ORDINAL_OFFSET: u64 = 0x28;
/// Offset of the address table in the XEX export table.
const ADDRESSES_OFFSET: u64 = 0x2C;

/// A function or variable the module exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// Ordinal of the export.
    pub ordinal: u32,
    /// Guest address of the export.
    pub address: u32,
    /// Name of the export, if the module has a PE export directory.
    pub name: Option<String>,
}

/// Reads the XEX export table, if the module has one.
pub(crate) fn read_export_table(image: &[u8], header: &Header) -> Result<Vec<Export>> {
    let table = header.security.export_table;
    if table == 0 {
        return Ok(Vec::new());
    }
    let reader = Reader::image(image);
    let base = u64::from(table.wrapping_sub(header.base_address()));
    for (index, expected) in EXPORT_TABLE_MAGIC.into_iter().enumerate() {
        let offset = base + index as u64 * 4;
        let found = reader.be_u32(offset, "export_table.magic")?;
        if found != expected {
            let kind = ErrorKind::BadMagic { expected, found };
            return Err(reader.error(offset, "export_table.magic", kind));
        }
    }
    // The stored image base is the high half of the address.
    let high = reader.be_u32(base + IMAGE_BASE_OFFSET, "export_table.image_base")? << 16;
    let count = u64::from(reader.be_u32(base + COUNT_OFFSET, "export_table.count")?);
    let first = reader.be_u32(base + BASE_ORDINAL_OFFSET, "export_table.base")?;
    let addresses = base + ADDRESSES_OFFSET;
    reader.bytes(addresses, count * 4, "export_table.addresses")?;
    let mut exports = Vec::new();
    for index in 0..count {
        let offset = reader.be_u32(addresses + index * 4, "export_table.addresses")?;
        // A zero entry is an ordinal the module leaves unassigned.
        if offset != 0 {
            exports.push(Export {
                // `count` was checked against the image size, so the index fits in 32 bits.
                ordinal: first.wrapping_add(index as u32),
                address: high.wrapping_add(offset),
                name: None,
            });
        }
    }
    Ok(exports)
}

/// Reads the PE export directory named by the `exports_by_name` optional header, if there is one.
///
/// As in Xenia, the directory and its tables are little-endian and the offsets it holds are
/// relative to the directory itself.
pub(crate) fn read_named_exports(
    file: &[u8],
    image: &[u8],
    header: &Header,
) -> Result<Vec<Export>> {
    let Some((_, location)) = header.optional_data(file, key::EXPORTS_BY_NAME)? else {
        return Ok(Vec::new());
    };
    let optional = Reader::file(location);
    let directory = u64::from(optional.be_u32(0, "optional.exports_by_name.offset")?);

    let reader = Reader::image(image);
    let field = |name| format!("export_directory.{name}");
    let first = reader.le_u32(directory + 16, field("base"))?;
    let functions = u64::from(reader.le_u32(directory + 20, field("number_of_functions"))?);
    let names = u64::from(reader.le_u32(directory + 24, field("number_of_names"))?);
    let function_table = directory + u64::from(reader.le_u32(directory + 28, field("functions"))?);
    let name_table = directory + u64::from(reader.le_u32(directory + 32, field("names"))?);
    let ordinal_table = directory + u64::from(reader.le_u32(directory + 36, field("ordinals"))?);
    reader.bytes(function_table, functions * 4, field("functions"))?;
    reader.bytes(name_table, names * 4, field("names"))?;
    reader.bytes(ordinal_table, names * 2, field("ordinals"))?;

    let mut exports = Vec::new();
    for index in 0..names {
        let function = u64::from(reader.le_u16(ordinal_table + index * 2, field("ordinals"))?);
        let rva = reader.le_u32(function_table + function * 4, field("functions"))?;
        let name_offset = reader.le_u32(name_table + index * 4, field("names"))?;
        let name = reader.c_string(directory + u64::from(name_offset), field("names"))?;
        exports.push(Export {
            // `function` is a 16-bit value.
            ordinal: first.wrapping_add(function as u32),
            address: header.base_address().wrapping_add(rva),
            name: Some(name),
        });
    }
    Ok(exports)
}

/// Combines both sources by ordinal, keeping them sorted. The address from the XEX table wins, as
/// it does for a loader, and names come from the PE directory.
pub(crate) fn merge(table: Vec<Export>, named: Vec<Export>) -> Vec<Export> {
    let mut by_ordinal: BTreeMap<u32, Export> = named
        .into_iter()
        .map(|export| (export.ordinal, export))
        .collect();
    for export in table {
        by_ordinal
            .entry(export.ordinal)
            .and_modify(|existing| existing.address = export.address)
            .or_insert(export);
    }
    by_ordinal.into_values().collect()
}
