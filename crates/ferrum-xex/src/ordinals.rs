// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Ordinal-to-name tables of the system libraries.
//!
//! The data comes from Xenia's `src/xenia/kernel/xboxkrnl/xboxkrnl_table.inc` and
//! `src/xenia/kernel/xam/xam_table.inc`, kept verbatim under `tables/xenia/` with their BSD 3-Clause
//! license and attribution. See `tables/xenia/README.md`.

use std::sync::OnceLock;

/// Xenia's `xboxkrnl_table.inc`.
const XBOXKRNL_TABLE: &str = include_str!("../tables/xenia/xboxkrnl_table.inc");
/// Xenia's `xam_table.inc`.
const XAM_TABLE: &str = include_str!("../tables/xenia/xam_table.inc");

/// The license of the ordinal tables, for binaries that have to reproduce it.
pub const TABLES_LICENSE: &str = include_str!("../tables/xenia/LICENSE");

/// What an import refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// A function, called through a thunk in the image.
    Function,
    /// A variable, whose address the loader writes into a slot of the image.
    Variable,
}

/// One entry of an ordinal table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrdinalEntry {
    /// Ordinal of the export.
    pub ordinal: u16,
    /// Name of the export.
    pub name: &'static str,
    /// Whether the export is a function or a variable.
    pub kind: ImportKind,
}

/// A system library whose exports are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownLibrary {
    /// `xboxkrnl.exe`, the kernel.
    Xboxkrnl,
    /// `xam.xex`, the system application layer.
    Xam,
}

impl KnownLibrary {
    /// Recognizes a library by the file name an import table gives it. As in Xenia, directories
    /// and the extension are ignored; unlike there, so is case.
    pub fn from_file_name(name: &str) -> Option<Self> {
        let file = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let stem = file.split('.').next().unwrap_or(file);
        if stem.eq_ignore_ascii_case("xboxkrnl") {
            Some(Self::Xboxkrnl)
        } else if stem.eq_ignore_ascii_case("xam") {
            Some(Self::Xam)
        } else {
            None
        }
    }

    /// Returns the library's exports, sorted by ordinal.
    pub fn table(self) -> &'static [OrdinalEntry] {
        static XBOXKRNL: OnceLock<Vec<OrdinalEntry>> = OnceLock::new();
        static XAM: OnceLock<Vec<OrdinalEntry>> = OnceLock::new();
        match self {
            Self::Xboxkrnl => XBOXKRNL.get_or_init(|| parse_table(XBOXKRNL_TABLE)),
            Self::Xam => XAM.get_or_init(|| parse_table(XAM_TABLE)),
        }
    }

    /// Finds an export by ordinal.
    pub fn lookup(self, ordinal: u16) -> Option<&'static OrdinalEntry> {
        let table = self.table();
        let index = table
            .binary_search_by_key(&ordinal, |entry| entry.ordinal)
            .ok()?;
        table.get(index)
    }
}

/// Parses a table. Lines other than `XE_EXPORT` entries are comments and are skipped.
fn parse_table(text: &'static str) -> Vec<OrdinalEntry> {
    let mut entries: Vec<_> = text.lines().filter_map(parse_line).collect();
    entries.sort_by_key(|entry| entry.ordinal);
    entries
}

/// Parses `XE_EXPORT(module, 0xORDINAL, Name, kKind),`.
fn parse_line(line: &'static str) -> Option<OrdinalEntry> {
    let arguments = line.trim().strip_prefix("XE_EXPORT(")?;
    let arguments = arguments.split(')').next()?;
    let mut fields = arguments.split(',').map(str::trim);
    let _module = fields.next()?;
    let ordinal = fields.next()?.strip_prefix("0x")?;
    let name = fields.next()?;
    let kind = match fields.next()? {
        "kFunction" => ImportKind::Function,
        "kVariable" => ImportKind::Variable,
        _ => return None,
    };
    Some(OrdinalEntry {
        ordinal: u16::from_str_radix(ordinal, 16).ok()?,
        name,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_line_parses() {
        for (library, text) in [
            (KnownLibrary::Xboxkrnl, XBOXKRNL_TABLE),
            (KnownLibrary::Xam, XAM_TABLE),
        ] {
            let lines = text.matches("XE_EXPORT(").count();
            assert!(lines > 900, "{library:?}: {lines}");
            assert_eq!(library.table().len(), lines, "{library:?}");
        }
    }

    #[test]
    fn tables_are_sorted_without_repeated_ordinals() {
        for library in [KnownLibrary::Xboxkrnl, KnownLibrary::Xam] {
            let table = library.table();
            assert!(
                table.windows(2).all(|w| w[0].ordinal < w[1].ordinal),
                "{library:?}"
            );
        }
    }

    #[test]
    fn the_tables_keep_their_attribution_and_license() {
        for text in [XBOXKRNL_TABLE, XAM_TABLE] {
            assert!(text.contains("Xenia : Xbox 360 Emulator Research Project"));
            assert!(text.contains("Copyright 2021 Ben Vanik"));
        }
        assert!(TABLES_LICENSE.contains("Copyright (c) 2015, Ben Vanik."));
        assert!(TABLES_LICENSE.contains("Redistributions in binary form"));
    }

    #[test]
    fn looks_up_functions_and_variables() {
        let kernel = KnownLibrary::Xboxkrnl;
        for (ordinal, name, kind) in [
            (0x0001, "DbgBreakPoint", ImportKind::Function),
            (0x000D, "ExCreateThread", ImportKind::Function),
            (0x0059, "KeDebugMonitorData", ImportKind::Variable),
            (0x0156, "XboxHardwareInfo", ImportKind::Variable),
            (0x01AE, "ExLoadedCommandLine", ImportKind::Variable),
        ] {
            let entry = kernel.lookup(ordinal).unwrap();
            assert_eq!((entry.name, entry.kind), (name, kind));
        }
        let xam = KnownLibrary::Xam.lookup(0x0191).unwrap();
        assert_eq!(xam.name, "XamInputGetState");
        assert_eq!(xam.kind, ImportKind::Function);
        assert_eq!(kernel.lookup(0x7FFF), None);
        assert_eq!(KnownLibrary::Xam.lookup(0), None);
    }

    #[test]
    fn recognizes_libraries_by_file_name() {
        for name in [
            "xboxkrnl.exe",
            "XBOXKRNL.EXE",
            "xboxkrnl",
            r"\Device\xboxkrnl.exe",
        ] {
            assert_eq!(
                KnownLibrary::from_file_name(name),
                Some(KnownLibrary::Xboxkrnl),
                "{name}"
            );
        }
        for name in ["xam.xex", "XAM.XEX", "dir/xam.xex"] {
            assert_eq!(
                KnownLibrary::from_file_name(name),
                Some(KnownLibrary::Xam),
                "{name}"
            );
        }
        for name in ["", "xbdm.xex", "game.exe", "xamx.xex"] {
            assert_eq!(KnownLibrary::from_file_name(name), None, "{name}");
        }
    }

    #[test]
    fn malformed_lines_are_skipped() {
        for line in [
            "// a comment",
            "XE_EXPORT(xam, 0x1, Name),",
            "XE_EXPORT(xam, 1, Name, kFunction),",
            "XE_EXPORT(xam, 0x1, Name, kOther),",
            "XE_EXPORT(xam, 0x10000, Name, kFunction),",
        ] {
            assert_eq!(parse_line(line), None, "{line}");
        }
    }
}
