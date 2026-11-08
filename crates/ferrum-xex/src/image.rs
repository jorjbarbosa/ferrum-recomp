// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The result of parsing a XEX2 file: its headers and the image they describe.

use std::fmt;

use crate::crypto::MasterKey;
use crate::error::{Error, Result};
use crate::exports::{self, Export};
use crate::header::{Header, TlsInfo};
use crate::imports::{self, ImportLibrary};
use crate::ordinals::ImportKind;
use crate::payload;
use crate::pe::{self, PeHeaders, RuntimeFunction, Section};

/// Something suspicious in a file that does not stop it from being used.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// The image does not match the digests of the security info, which happens when a file is
    /// modified after signing.
    ImageDigestMismatch {
        /// Index of the first run of pages that does not match.
        page_run: usize,
    },
    /// Entries of `.pdata` fall outside the sections marked as code.
    PdataOutsideCode {
        /// How many entries do.
        count: usize,
        /// Address of the first one.
        first: u32,
    },
    /// The PE export directory could not be read, so exports have no names.
    NamedExportsUnreadable(Error),
    /// An import library has no ordinal table, so its imports have no names.
    UnknownImportLibrary {
        /// File name of the library.
        library: String,
    },
    /// An import ordinal is not in the table of its library, so it has no name.
    UnknownImportOrdinal {
        /// File name of the library.
        library: String,
        /// The ordinal.
        ordinal: u16,
    },
    /// The records of an import disagree with the kind the table gives it.
    ImportKindMismatch {
        /// File name of the library.
        library: String,
        /// The ordinal.
        ordinal: u16,
        /// Name of the export.
        name: &'static str,
        /// The kind the table gives the export.
        kind: ImportKind,
    },
    /// Two records of the same type name the same ordinal, and the last one was kept.
    DuplicateImportRecord {
        /// File name of the library.
        library: String,
        /// The ordinal.
        ordinal: u16,
    },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Warning::ImageDigestMismatch { page_run } => write!(
                f,
                "the image does not match the security info digests, starting at page run \
                 {page_run}; it was modified after signing or is corrupt"
            ),
            Warning::PdataOutsideCode { count, first } => write!(
                f,
                "{count} .pdata entries fall outside the code sections, the first at {first:#010x}"
            ),
            Warning::NamedExportsUnreadable(error) => {
                write!(f, "the PE export directory is unreadable: {error}")
            }
            Warning::UnknownImportLibrary { library } => {
                write!(f, "no ordinal table for import library {library}")
            }
            Warning::UnknownImportOrdinal { library, ordinal } => {
                write!(
                    f,
                    "{library} ordinal {ordinal:#x} is not in its ordinal table"
                )
            }
            Warning::ImportKindMismatch {
                library,
                ordinal,
                name,
                kind,
            } => write!(
                f,
                "{library} ordinal {ordinal:#x} ({name}) is a {} in the table but its records \
                 say otherwise",
                match kind {
                    ImportKind::Function => "function",
                    ImportKind::Variable => "variable",
                }
            ),
            Warning::DuplicateImportRecord { library, ordinal } => {
                write!(
                    f,
                    "{library} ordinal {ordinal:#x} has two records of the same type"
                )
            }
        }
    }
}

/// A decrypted and decompressed module, laid out as it will be in guest memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Guest address of the first byte.
    pub base: u32,
    /// Guest address of the entry point.
    pub entry: u32,
    /// The image bytes.
    pub data: Vec<u8>,
    /// The PE headers.
    pub pe: PeHeaders,
    /// The sections the PE section table declares, in table order. Some may lie outside `data`.
    pub sections: Vec<Section>,
    /// The entries of `.pdata`, in table order.
    pub pdata: Vec<RuntimeFunction>,
    /// The import libraries, in file order.
    pub imports: Vec<ImportLibrary>,
    /// The exports, sorted by ordinal.
    pub exports: Vec<Export>,
    /// The thread-local storage layout.
    pub tls: Option<TlsInfo>,
}

impl Image {
    /// Returns the bytes at a guest address, or `None` if they are not all in the image.
    pub fn bytes_at(&self, address: u32, len: usize) -> Option<&[u8]> {
        let start = usize::try_from(address.checked_sub(self.base)?).ok()?;
        self.data.get(start..start.checked_add(len)?)
    }

    /// Returns the bytes of a section that are in the image, which may be fewer than its size.
    pub fn section_data(&self, section: &Section) -> &[u8] {
        let image_end = u64::from(self.base) + self.data.len() as u64;
        let available = image_end
            .min(section.end())
            .saturating_sub(section.address.into());
        let available = usize::try_from(available).unwrap_or(0);
        self.bytes_at(section.address, available)
            .unwrap_or_default()
    }

    /// Returns the first section with the given name.
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|section| section.name == name)
    }
}

/// A parsed XEX2 file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xex {
    /// The file headers.
    pub header: Header,
    /// The master key that decrypted the payload, or `None` if it was not encrypted.
    pub key: Option<MasterKey>,
    /// The module image.
    pub image: Image,
    /// Non-fatal problems found while parsing.
    pub warnings: Vec<Warning>,
}

impl Xex {
    /// Parses a whole XEX2 file.
    pub fn parse(file: &[u8]) -> Result<Self> {
        let header = Header::parse(file)?;
        let decoded = payload::decode(file, &header)?;
        let data = decoded.image;
        let base = header.base_address();
        let pe = pe::parse(&data, base)?;
        let mut warnings = Vec::new();
        if let Some(page_run) = payload::first_bad_page_run(&data, &header.security) {
            warnings.push(Warning::ImageDigestMismatch { page_run });
        }
        warnings.extend(check_pdata(&pe.pdata, &pe.sections));
        let named = exports::read_named_exports(file, &data, &header).unwrap_or_else(|error| {
            warnings.push(Warning::NamedExportsUnreadable(error));
            Vec::new()
        });
        let exports = exports::merge(exports::read_export_table(&data, &header)?, named);
        let imports = imports::read_imports(file, &data, &header, &mut warnings)?;
        let image = Image {
            base,
            entry: header
                .entry_point
                .unwrap_or_else(|| base.wrapping_add(pe.headers.entry_rva)),
            data,
            pe: pe.headers,
            sections: pe.sections,
            pdata: pe.pdata,
            imports,
            exports,
            tls: header.tls,
        };
        Ok(Self {
            header,
            key: decoded.key,
            image,
            warnings,
        })
    }
}

/// Reports `.pdata` entries that are not inside a code section.
fn check_pdata(pdata: &[RuntimeFunction], sections: &[Section]) -> Option<Warning> {
    let in_code = |function: &RuntimeFunction| {
        sections.iter().any(|section| {
            section.is_code() && section.contains(function.begin) && function.end() <= section.end()
        })
    };
    let mut outside = pdata.iter().filter(|function| !in_code(function));
    let first = outside.next()?.begin;
    Some(Warning::PdataOutsideCode {
        count: outside.count() + 1,
        first,
    })
}
