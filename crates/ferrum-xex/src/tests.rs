// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Tests of [`Xex::parse`] over complete synthetic modules.

use crate::error::{ErrorKind, Location};
use crate::fixtures::sample::{DATA_FLAGS, RDATA_FLAGS, RELOC_FLAGS, TEXT_FLAGS};
use crate::fixtures::sample::{ImportSpec, LibrarySpec, SampleLayout};
use crate::fixtures::sample::{NT_OFFSET, PDATA_RVA, SECTION_TABLE};
use crate::fixtures::{FixtureCompression, FixtureEncryption, XexBuilder};
use crate::header::key;
use crate::{Export, Import, ImportKind, RuntimeFunction, Warning, Xex};

/// Parses a module whose plain image was changed by `edit`, keeping the digests valid.
fn parse_edited(edit: impl FnOnce(&mut Vec<u8>)) -> crate::Result<Xex> {
    let mut builder = SampleLayout::default().builder();
    edit(&mut builder.image);
    Xex::parse(&builder.build().bytes)
}

fn parse_sample() -> Xex {
    Xex::parse(&SampleLayout::default().builder().build().bytes).unwrap()
}

#[test]
fn reconstructs_the_image_under_every_key_and_compression() {
    let expected = SampleLayout::default().builder().image;
    for compression in [
        FixtureCompression::None,
        FixtureCompression::Basic,
        FixtureCompression::LzxUncompressedBlocks,
        FixtureCompression::LzxVerbatimBlocks,
    ] {
        for encryption in [
            FixtureEncryption::None,
            FixtureEncryption::Retail,
            FixtureEncryption::Devkit,
        ] {
            let mut builder = SampleLayout::default().builder();
            builder.compression = compression.clone();
            builder.encryption = encryption;
            let xex = Xex::parse(&builder.build().bytes).unwrap();
            assert_eq!(xex.image.data, expected, "{compression:?} {encryption:?}");
            assert_eq!(xex.warnings, [], "{compression:?} {encryption:?}");
        }
    }
}

#[test]
fn base_and_entry_come_from_the_headers() {
    let xex = parse_sample();
    assert_eq!(xex.image.base, 0x8200_0000);
    assert_eq!(xex.image.entry, 0x8201_0000);
    assert_eq!(xex.image.pe.image_base, 0x8200_0000);
    assert_eq!(xex.image.pe.entry_rva, 0x1_0000);
    assert_eq!(xex.image.pe.time_date_stamp, 0x5F5E_1000);
    assert_eq!(xex.image.pe.data_directories.len(), 16);
    assert_eq!(xex.image.pe.data_directories[3].rva, PDATA_RVA);
}

#[test]
fn the_entry_point_falls_back_to_the_pe_header() {
    let built = SampleLayout::default().builder().build();
    let mut file = built.bytes.clone();
    let entry = built.optional_entry_offset(key::ENTRY_POINT);
    file[entry..entry + 4].copy_from_slice(&0x0BAD_0000u32.to_be_bytes());
    let xex = Xex::parse(&file).unwrap();
    assert_eq!(xex.header.entry_point, None);
    assert_eq!(xex.image.entry, 0x8201_0000);
}

#[test]
fn sections_are_listed_as_declared_with_guest_addresses() {
    let xex = parse_sample();
    let listed: Vec<_> = xex
        .image
        .sections
        .iter()
        .map(|s| {
            (
                s.name.as_str(),
                s.address,
                s.virtual_size,
                s.raw_pointer,
                s.characteristics,
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            (".rdata", 0x8200_0400, 0x500, 0x400, RDATA_FLAGS),
            (".pdata", 0x8200_0A00, 0x20, 0xA00, RDATA_FLAGS),
            (".text", 0x8201_0000, 0x800, 0xC00, TEXT_FLAGS),
            (".data", 0x8202_0000, 0x200, 0x1400, DATA_FLAGS),
            (".reloc", 0x8204_0000, 0x1000, 0x1600, RELOC_FLAGS),
        ]
    );
}

#[test]
fn section_permissions_follow_the_characteristics() {
    let xex = parse_sample();
    let text = xex.image.section(".text").unwrap();
    assert!(text.is_code() && text.is_readable() && text.is_executable());
    assert!(!text.is_writable());
    let data = xex.image.section(".data").unwrap();
    assert!(data.is_readable() && data.is_writable());
    assert!(!data.is_code() && !data.is_executable());
    let rdata = xex.image.section(".rdata").unwrap();
    assert!(rdata.is_readable());
    assert!(!rdata.is_writable() && !rdata.is_executable());
}

#[test]
fn section_data_is_found_by_virtual_address_and_not_by_raw_pointer() {
    let xex = parse_sample();
    let text = xex.image.section(".text").unwrap();
    assert_ne!(u64::from(text.raw_pointer), 0x1_0000);
    let bytes = xex.image.section_data(text);
    assert_eq!(bytes.len(), 0x800);
    assert_eq!(bytes[..4], [0, 1, 2, 3]);
    assert_eq!(
        xex.image.section_data(xex.image.section(".data").unwrap())[0],
        0xDA
    );
}

#[test]
fn a_section_past_the_end_of_the_image_is_listed_but_has_no_data() {
    let xex = parse_sample();
    let reloc = xex.image.section(".reloc").unwrap();
    assert!(reloc.end() > u64::from(xex.image.base) + xex.image.data.len() as u64);
    assert_eq!(xex.image.section_data(reloc), []);
    assert_eq!(xex.warnings, []);
}

#[test]
fn a_section_overlapping_the_end_of_the_image_is_cut_short() {
    let layout = SampleLayout::default();
    let xex = parse_edited(|image| {
        // Move .reloc back so that it starts 0x10 bytes before the end of the image.
        let at = SECTION_TABLE + 4 * 40 + 12;
        let rva = layout.image_size() - 0x10;
        image[at..at + 4].copy_from_slice(&rva.to_le_bytes());
    })
    .unwrap();
    let reloc = xex.image.section(".reloc").unwrap();
    assert_eq!(xex.image.section_data(reloc).len(), 0x10);
}

#[test]
fn bytes_at_stays_inside_the_image() {
    let xex = parse_sample();
    let image = &xex.image;
    assert_eq!(image.bytes_at(0x8200_0000, 2), Some(&b"MZ"[..]));
    assert_eq!(image.bytes_at(0x8201_0001, 1), Some(&[1][..]));
    assert_eq!(image.bytes_at(0x81FF_FFFF, 1), None);
    assert_eq!(image.bytes_at(0x8204_0000, 1), None);
    assert_eq!(image.bytes_at(0x8203_FFFF, 2), None);
    assert_eq!(image.bytes_at(0x8203_FFFF, usize::MAX), None);
}

#[test]
fn pdata_entries_are_decoded_and_zero_padding_is_dropped() {
    let xex = parse_sample();
    let pdata = &xex.image.pdata;
    assert_eq!(pdata.len(), 3);

    assert_eq!(pdata[0].begin, 0x8201_0000);
    assert_eq!(pdata[0].prolog_words(), 2);
    assert_eq!(pdata[0].length_words(), 4);
    assert_eq!(pdata[0].size(), 16);
    assert_eq!(pdata[0].end(), 0x8201_0010);
    assert!(pdata[0].is_32bit());
    assert!(!pdata[0].has_exception_handler());

    assert_eq!(pdata[1].begin, 0x8201_0010);
    assert_eq!(pdata[1].prolog_words(), 3);
    assert_eq!(pdata[1].size(), 32);
    assert!(pdata[1].is_32bit());
    assert!(pdata[1].has_exception_handler());

    assert_eq!(pdata[2].begin, 0x8201_0030);
    assert_eq!(pdata[2].prolog_words(), 0);
    assert!(!pdata[2].is_32bit());
}

#[test]
fn the_largest_function_length_does_not_touch_the_flags() {
    let function = RuntimeFunction {
        begin: 0xFFFF_FFF0,
        raw: 0x3F_FFFF << 8,
    };
    assert_eq!(function.length_words(), 0x3F_FFFF);
    assert_eq!(function.size(), 0xFF_FFFC);
    assert_eq!(function.end(), 0xFFFF_FFF0 + 0xFF_FFFC);
    assert!(!function.is_32bit() && !function.has_exception_handler());
    assert_eq!(function.prolog_words(), 0);
}

#[test]
fn the_exception_directory_wins_over_the_section_named_pdata() {
    let xex = parse_edited(|image| {
        // Move the table and point the directory at it, leaving the section header stale.
        let (table, entry) = (0x700, NT_OFFSET + 0x18 + 0x60 + 3 * 8);
        let bytes = image[PDATA_RVA as usize..PDATA_RVA as usize + 8].to_vec();
        image[table..table + 8].copy_from_slice(&bytes);
        image[entry..entry + 4].copy_from_slice(&(table as u32).to_le_bytes());
        image[entry + 4..entry + 8].copy_from_slice(&8u32.to_le_bytes());
    })
    .unwrap();
    assert_eq!(xex.image.pdata.len(), 1);
    assert_eq!(xex.image.pdata[0].begin, 0x8201_0000);
}

#[test]
fn pdata_falls_back_to_the_section_when_the_directory_is_empty() {
    let xex = parse_edited(|image| {
        let entry = NT_OFFSET + 0x18 + 0x60 + 3 * 8;
        image[entry..entry + 8].fill(0);
    })
    .unwrap();
    assert_eq!(xex.image.pdata.len(), 3);
}

#[test]
fn a_module_without_pdata_has_no_entries() {
    let xex = parse_edited(|image| {
        let entry = NT_OFFSET + 0x18 + 0x60 + 3 * 8;
        image[entry..entry + 8].fill(0);
        let name = SECTION_TABLE + 40;
        image[name..name + 6].copy_from_slice(b".other");
    })
    .unwrap();
    assert_eq!(xex.image.pdata, []);
}

#[test]
fn an_exception_directory_outside_the_image_is_an_error() {
    let err = parse_edited(|image| {
        let entry = NT_OFFSET + 0x18 + 0x60 + 3 * 8;
        image[entry..entry + 4].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());
    })
    .unwrap_err();
    assert_eq!(err.field, "pe.exception_directory");
    assert_eq!(err.location, Location::Image(0x7FFF_0000));
}

#[test]
fn pdata_outside_the_code_sections_is_a_warning() {
    let xex = parse_edited(|image| {
        let at = PDATA_RVA as usize + 8;
        image[at..at + 4].copy_from_slice(&0x8202_0000u32.to_be_bytes());
        let last = PDATA_RVA as usize + 16;
        image[last..last + 4].copy_from_slice(&0x820F_0000u32.to_be_bytes());
    })
    .unwrap();
    assert_eq!(
        xex.warnings,
        [Warning::PdataOutsideCode {
            count: 2,
            first: 0x8202_0000
        }]
    );
    assert!(xex.warnings[0].to_string().contains("0x82020000"));
}

#[test]
fn exports_come_from_the_xex_table_and_skip_unassigned_ordinals() {
    let exports = parse_sample().image.exports;
    assert_eq!(
        exports,
        [
            Export {
                ordinal: 1,
                address: 0x8201_0000,
                name: None
            },
            Export {
                ordinal: 3,
                address: 0x8201_0010,
                name: None
            },
        ]
    );
}

#[test]
fn the_pe_export_data_directory_is_not_trusted() {
    // The sample's directory points past the end of the image, and that must not matter.
    let xex = parse_sample();
    assert!(u64::from(xex.image.pe.data_directories[0].rva) > xex.image.data.len() as u64);
    assert_eq!(xex.warnings, []);
}

#[test]
fn a_module_without_an_export_table_has_no_exports() {
    let mut builder = SampleLayout::default().builder();
    builder.export_table = 0;
    assert_eq!(
        Xex::parse(&builder.build().bytes).unwrap().image.exports,
        []
    );
}

#[test]
fn a_bad_export_table_magic_is_an_error_at_the_table() {
    let err = parse_edited(|image| image[0x404] ^= 1).unwrap_err();
    assert_eq!(err.field, "export_table.magic");
    assert_eq!(err.location, Location::Image(0x404));
    assert!(matches!(err.kind, ErrorKind::BadMagic { .. }));
}

#[test]
fn an_export_table_count_past_the_image_is_an_error() {
    let err = parse_edited(|image| {
        image[0x424..0x428].copy_from_slice(&u32::MAX.to_be_bytes());
    })
    .unwrap_err();
    assert_eq!(err.field, "export_table.addresses");
    assert_eq!(err.location, Location::Image(0x42C));
    assert!(matches!(err.kind, ErrorKind::Truncated { .. }));
}

#[test]
fn an_export_table_outside_the_image_is_an_error() {
    let mut builder = SampleLayout::default().builder();
    builder.export_table = 0x9000_0000;
    let err = Xex::parse(&builder.build().bytes).unwrap_err();
    assert_eq!(err.field, "export_table.magic");
    assert!(matches!(err.kind, ErrorKind::Truncated { .. }));
}

/// Lays out a PE export directory at `at` in the image, naming function 2 `second`.
fn write_export_directory(image: &mut [u8], at: usize) {
    let le = |value: u32| value.to_le_bytes();
    image[at + 16..at + 20].copy_from_slice(&le(1));
    image[at + 20..at + 24].copy_from_slice(&le(3));
    image[at + 24..at + 28].copy_from_slice(&le(1));
    image[at + 28..at + 32].copy_from_slice(&le(0x40));
    image[at + 32..at + 36].copy_from_slice(&le(0x50));
    image[at + 36..at + 40].copy_from_slice(&le(0x54));
    image[at + 0x40..at + 0x44].copy_from_slice(&le(0x1_0000));
    image[at + 0x44..at + 0x48].copy_from_slice(&le(0x1_0020));
    image[at + 0x48..at + 0x4C].copy_from_slice(&le(0x1_0010));
    image[at + 0x50..at + 0x54].copy_from_slice(&le(0x60));
    image[at + 0x54..at + 0x56].copy_from_slice(&2u16.to_le_bytes());
    image[at + 0x60..at + 0x67].copy_from_slice(b"second\0");
}

/// A module whose `exports_by_name` optional header points at a directory at offset `0x500`.
fn builder_with_named_exports() -> XexBuilder {
    let mut builder = SampleLayout::default().builder();
    write_export_directory(&mut builder.image, 0x500);
    let mut location = 0x500u32.to_be_bytes().to_vec();
    location.extend_from_slice(&0x100u32.to_be_bytes());
    builder
        .extra_optional
        .push((key::EXPORTS_BY_NAME, location));
    builder
}

#[test]
fn names_from_the_export_directory_join_the_xex_table_by_ordinal() {
    let xex = Xex::parse(&builder_with_named_exports().build().bytes).unwrap();
    assert_eq!(xex.warnings, []);
    assert_eq!(
        xex.image.exports,
        [
            Export {
                ordinal: 1,
                address: 0x8201_0000,
                name: None
            },
            Export {
                ordinal: 3,
                // The address of the XEX table wins over the 0x82010010 in the directory.
                address: 0x8201_0010,
                name: Some("second".to_owned())
            },
        ]
    );
}

#[test]
fn named_exports_stand_alone_without_a_xex_table() {
    let mut builder = builder_with_named_exports();
    builder.export_table = 0;
    let exports = Xex::parse(&builder.build().bytes).unwrap().image.exports;
    assert_eq!(
        exports,
        [Export {
            ordinal: 3,
            address: 0x8201_0010,
            name: Some("second".to_owned())
        }]
    );
}

#[test]
fn an_unreadable_export_directory_is_a_warning() {
    let mut builder = builder_with_named_exports();
    // The count of names now runs the name table off the end of the image.
    builder.image[0x500 + 24..0x500 + 28].copy_from_slice(&u32::MAX.to_le_bytes());
    let xex = Xex::parse(&builder.build().bytes).unwrap();
    assert!(matches!(
        xex.warnings[..],
        [Warning::NamedExportsUnreadable(_)]
    ));
    assert!(xex.warnings[0].to_string().contains("export_directory"));
    assert_eq!(xex.image.exports.len(), 2);
}

#[test]
fn tls_info_reaches_the_image() {
    let tls = parse_sample().image.tls.unwrap();
    assert_eq!(tls.slot_count, 64);
    assert_eq!(tls.raw_data_address, 0x8201_0100);
    assert_eq!(tls.data_size, 0x20);
    assert_eq!(tls.raw_data_size, 0x10);
}

#[test]
fn a_modified_image_is_a_warning() {
    // Edit the plain image after the digests were computed.
    let mut built = SampleLayout::default().builder().build();
    let edit = built.header_size as usize + 0x1_0010;
    built.bytes[edit] ^= 1;
    let xex = Xex::parse(&built.bytes).unwrap();
    assert_eq!(xex.warnings, [Warning::ImageDigestMismatch { page_run: 1 }]);
    assert!(xex.warnings[0].to_string().contains("page run 1"));
}

/// Rewrites a little-endian `u16` of the NT headers and returns the parse error.
fn nt_u16_error(offset: usize, value: u16) -> crate::Error {
    parse_edited(|image| {
        let at = NT_OFFSET + offset;
        image[at..at + 2].copy_from_slice(&value.to_le_bytes());
    })
    .unwrap_err()
}

#[test]
fn rejects_images_that_are_not_xbox_powerpc_pes() {
    let nt = NT_OFFSET as u64;
    let cases: [(usize, u16, &str); 5] = [
        (4, 0x014C, "pe.file.machine"),
        (0x14, 0xF0, "pe.file.size_of_optional_header"),
        (0x16, 0x0002, "pe.file.characteristics"),
        (0x18, 0x020B, "pe.optional.magic"),
        (0x18 + 0x44, 2, "pe.optional.subsystem"),
    ];
    for (offset, value, field) in cases {
        let err = nt_u16_error(offset, value);
        assert_eq!(err.field, field);
        assert_eq!(err.location, Location::Image(nt + offset as u64));
        assert!(matches!(err.kind, ErrorKind::Unsupported { .. }), "{err}");
    }
}

#[test]
fn rejects_a_bad_nt_signature() {
    let err = parse_edited(|image| image[NT_OFFSET] = b'X').unwrap_err();
    assert_eq!(err.field, "pe.nt.signature");
    assert_eq!(err.location, Location::Image(NT_OFFSET as u64));
    assert!(matches!(err.kind, ErrorKind::BadMagic { .. }));
}

#[test]
fn rejects_nt_headers_outside_the_image() {
    let err = parse_edited(|image| {
        image[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    })
    .unwrap_err();
    assert_eq!(err.field, "pe.nt.signature");
    assert_eq!(err.location, Location::Image(u32::MAX.into()));
}

#[test]
fn rejects_an_image_without_the_dos_signature() {
    let err = parse_edited(|image| image[0] = b'Z').unwrap_err();
    assert_eq!(err.field, "pe.dos.magic");
    assert_eq!(err.location, Location::Image(0));
}

#[test]
fn rejects_a_section_table_past_the_image() {
    let err = parse_edited(|image| {
        let at = NT_OFFSET + 6;
        image[at..at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    })
    .unwrap_err();
    assert!(err.field.starts_with("pe.sections["), "{err}");
    assert!(matches!(err.location, Location::Image(_)));
    assert!(matches!(err.kind, ErrorKind::Truncated { .. }));
}

/// Offset of the first slot from the image base, and of the first thunk, in the default layout.
const FIRST_SLOT: u32 = 0x8202_0100;
const FIRST_THUNK: u32 = 0x8201_0400;

/// A module with the given libraries.
fn parse_libraries(libraries: &[LibrarySpec]) -> Xex {
    let layout = SampleLayout::default();
    let mut builder = layout.builder();
    builder.image = layout.image();
    layout.with_imports(&mut builder, libraries);
    Xex::parse(&builder.build().bytes).unwrap()
}

fn spec(name: &'static str, imports: &[(u16, bool)]) -> LibrarySpec {
    LibrarySpec {
        name,
        imports: imports
            .iter()
            .map(|&(ordinal, thunk)| ImportSpec { ordinal, thunk })
            .collect(),
    }
}

#[test]
fn libraries_get_their_names_through_the_name_index() {
    // The fixture lists xboxkrnl first although xam comes first in the name table.
    let xex = parse_sample();
    let names: Vec<_> = xex.image.imports.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(names, ["xboxkrnl.exe", "xam.xex"]);
    let kernel = &xex.image.imports[0];
    assert_eq!(kernel.id, 0x1234_ABCD);
    assert_eq!(kernel.version.to_string(), "2.0.24.130");
    assert_eq!(kernel.min_version.to_string(), "2.0.22.134");
    assert_eq!(xex.header.security.import_table_count, 2);
}

#[test]
fn slots_and_thunks_of_an_ordinal_are_paired_into_one_function() {
    let xex = parse_sample();
    assert_eq!(xex.warnings, []);
    let kernel = &xex.image.imports[0].imports;
    assert_eq!(
        kernel.len(),
        3,
        "records must collapse into one per ordinal"
    );
    assert_eq!(
        kernel[0],
        Import {
            ordinal: 0x000D,
            name: Some("ExCreateThread"),
            kind: ImportKind::Function,
            slot: Some(FIRST_SLOT),
            thunk: Some(FIRST_THUNK),
        }
    );
    let xam = &xex.image.imports[1].imports;
    assert_eq!(xam[0].name, Some("XamInputGetState"));
    assert_eq!(xam[0].kind, ImportKind::Function);
    assert_eq!(xam[1].name, Some("XamShowMessageBoxUI"));
    assert_eq!(xam[1].thunk, Some(FIRST_THUNK + 2 * 16));
}

#[test]
fn a_slot_without_a_thunk_is_a_variable() {
    let xex = parse_sample();
    let kernel = &xex.image.imports[0].imports;
    assert_eq!(
        kernel[1],
        Import {
            ordinal: 0x0059,
            name: Some("KeDebugMonitorData"),
            kind: ImportKind::Variable,
            slot: Some(FIRST_SLOT + 8),
            thunk: None,
        }
    );
    assert_eq!(kernel[2].name, Some("XboxHardwareInfo"));
    assert_eq!(kernel[2].kind, ImportKind::Variable);
    assert_eq!(kernel[2].thunk, None);
}

#[test]
fn imports_are_sorted_by_ordinal() {
    let xex = parse_sample();
    let ordinals: Vec<_> = xex.image.imports[0]
        .imports
        .iter()
        .map(|i| i.ordinal)
        .collect();
    assert_eq!(ordinals, [0x000D, 0x0059, 0x0156]);
}

#[test]
fn an_unknown_ordinal_warns_and_infers_its_kind_from_the_records() {
    let xex = parse_libraries(&[spec("xboxkrnl.exe", &[(0x7FF0, true), (0x7FF1, false)])]);
    let imports = &xex.image.imports[0].imports;
    assert_eq!(imports[0].name, None);
    assert_eq!(imports[0].kind, ImportKind::Function);
    assert_eq!(imports[1].name, None);
    assert_eq!(imports[1].kind, ImportKind::Variable);
    assert_eq!(
        xex.warnings,
        [
            Warning::UnknownImportOrdinal {
                library: "xboxkrnl.exe".to_owned(),
                ordinal: 0x7FF0
            },
            Warning::UnknownImportOrdinal {
                library: "xboxkrnl.exe".to_owned(),
                ordinal: 0x7FF1
            },
        ]
    );
    assert!(xex.warnings[0].to_string().contains("0x7ff0"));
}

#[test]
fn a_library_without_a_table_warns_once_and_keeps_the_ordinals() {
    let xex = parse_libraries(&[spec("xbdm.xex", &[(0x10, true), (0x11, false)])]);
    let imports = &xex.image.imports[0].imports;
    assert_eq!(imports.len(), 2);
    assert_eq!(imports[0].name, None);
    assert_eq!(imports[0].kind, ImportKind::Function);
    assert_eq!(imports[1].kind, ImportKind::Variable);
    assert_eq!(
        xex.warnings,
        [Warning::UnknownImportLibrary {
            library: "xbdm.xex".to_owned()
        }]
    );
}

#[test]
fn the_table_wins_when_the_records_disagree_with_it() {
    // XboxHardwareInfo is a variable, and ExCreateThread a function.
    let xex = parse_libraries(&[spec("xboxkrnl.exe", &[(0x0156, true), (0x000D, false)])]);
    let imports = &xex.image.imports[0].imports;
    assert_eq!(imports[0].name, Some("ExCreateThread"));
    assert_eq!(imports[0].kind, ImportKind::Function);
    assert_eq!(imports[1].name, Some("XboxHardwareInfo"));
    assert_eq!(imports[1].kind, ImportKind::Variable);
    assert_eq!(xex.warnings.len(), 2);
    assert!(matches!(
        xex.warnings[0],
        Warning::ImportKindMismatch {
            ordinal: 0x000D,
            kind: ImportKind::Function,
            ..
        }
    ));
    assert!(xex.warnings[1].to_string().contains("XboxHardwareInfo"));
}

/// A plain module whose import table can be corrupted, and where that table starts.
fn imports_fixture() -> (crate::fixtures::BuiltXex, usize) {
    let built = SampleLayout::default().builder().build();
    let table = built.optional_data_offset(key::IMPORT_LIBRARIES);
    (built, table)
}

/// Where the first library entry starts in the default import table.
const FIRST_LIBRARY: usize = 12 + 8 + 16;

fn be32_at(file: &mut [u8], offset: usize, value: u32) {
    file[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn a_name_index_past_the_string_table_is_an_error() {
    let (mut built, table) = imports_fixture();
    let at = table + FIRST_LIBRARY + 0x24;
    built.bytes[at..at + 2].copy_from_slice(&7u16.to_be_bytes());
    let err = Xex::parse(&built.bytes).unwrap_err();
    assert_eq!(err.field, "import_libraries[0].name_index");
    assert_eq!(err.location, Location::File(at as u64));
}

#[test]
fn only_the_low_byte_of_the_name_index_counts() {
    let (mut built, table) = imports_fixture();
    let at = table + FIRST_LIBRARY + 0x24;
    built.bytes[at] = 0xAB;
    let xex = Xex::parse(&built.bytes).unwrap();
    assert_eq!(xex.image.imports[0].name, "xboxkrnl.exe");
}

#[test]
fn a_library_size_below_its_fixed_part_is_an_error() {
    let (mut built, table) = imports_fixture();
    be32_at(&mut built.bytes, table + FIRST_LIBRARY, 0x10);
    let err = Xex::parse(&built.bytes).unwrap_err();
    assert_eq!(err.field, "import_libraries[0].size");
    assert_eq!(err.location, Location::File((table + FIRST_LIBRARY) as u64));
    assert!(matches!(
        err.kind,
        ErrorKind::InvalidValue { value: 0x10, .. }
    ));
}

#[test]
fn a_zero_library_size_ends_the_list() {
    let (mut built, table) = imports_fixture();
    be32_at(&mut built.bytes, table + FIRST_LIBRARY, 0);
    assert_eq!(Xex::parse(&built.bytes).unwrap().image.imports, []);
}

#[test]
fn more_records_than_fit_in_the_entry_is_an_error() {
    let (mut built, table) = imports_fixture();
    let at = table + FIRST_LIBRARY + 0x26;
    built.bytes[at..at + 2].copy_from_slice(&u16::MAX.to_be_bytes());
    let err = Xex::parse(&built.bytes).unwrap_err();
    assert_eq!(err.field, "import_libraries[0].record_count");
    assert_eq!(err.location, Location::File(at as u64));
}

#[test]
fn a_record_outside_the_image_is_an_error_in_image_space() {
    let (mut built, table) = imports_fixture();
    let at = table + FIRST_LIBRARY + 0x28;
    be32_at(&mut built.bytes, at, 0x9000_0000);
    let err = Xex::parse(&built.bytes).unwrap_err();
    assert_eq!(err.field, "import_libraries[0].records[0]");
    assert_eq!(err.location, Location::Image(0x0E00_0000));
    assert!(matches!(err.kind, ErrorKind::Truncated { .. }));
}

#[test]
fn a_zero_record_address_is_skipped() {
    let (mut built, table) = imports_fixture();
    // The first record is the thunk of ExCreateThread. Without it only the slot remains.
    be32_at(&mut built.bytes, table + FIRST_LIBRARY + 0x28, 0);
    let xex = Xex::parse(&built.bytes).unwrap();
    let import = xex.image.imports[0].imports[0];
    assert_eq!(import.thunk, None);
    assert_eq!(import.slot, Some(FIRST_SLOT));
    assert_eq!(import.kind, ImportKind::Function);
}

#[test]
fn a_record_of_an_unknown_type_is_an_error_at_the_record() {
    let mut builder = SampleLayout::default().builder();
    // The first slot, in .data, gets record type 2.
    builder.image[0x2_0100] = 2;
    let err = Xex::parse(&builder.build().bytes).unwrap_err();
    assert_eq!(err.field, "import_libraries[0].records[1]");
    assert_eq!(err.location, Location::Image(0x2_0100));
    assert!(matches!(err.kind, ErrorKind::InvalidValue { value: 2, .. }));
}

#[test]
fn two_records_for_the_same_ordinal_and_type_warn() {
    let (mut built, table) = imports_fixture();
    // Make the slot of ExCreateThread be listed twice, in place of the thunk.
    let records = table + FIRST_LIBRARY + 0x28;
    be32_at(&mut built.bytes, records, FIRST_SLOT);
    let xex = Xex::parse(&built.bytes).unwrap();
    assert!(xex.warnings.contains(&Warning::DuplicateImportRecord {
        library: "xboxkrnl.exe".to_owned(),
        ordinal: 0x000D
    }));
}

#[test]
fn a_module_without_imports_has_none() {
    let mut builder = SampleLayout::default().builder();
    builder.extra_optional.clear();
    assert_eq!(
        Xex::parse(&builder.build().bytes).unwrap().image.imports,
        []
    );
}

#[test]
fn a_string_table_larger_than_the_header_is_an_error() {
    let (mut built, table) = imports_fixture();
    be32_at(&mut built.bytes, table + 4, 0x7FFF_0000);
    let err = Xex::parse(&built.bytes).unwrap_err();
    assert_eq!(err.field, "import_libraries.strings");
    assert_eq!(err.location, Location::File(table as u64 + 12));
}
