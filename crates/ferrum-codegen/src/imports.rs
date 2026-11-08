// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Imports: what a call to the thunk of an imported function becomes, and the root crate's
//! `imports.rs`, with a function per thunk for the table and the `load` that fills the slots.

use std::fmt::Write as _;

/// The library an import comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Library {
    /// `xboxkrnl.exe`, whose trait generated code reaches as `k.krnl`.
    Xboxkrnl,
    /// `xam.xex`, whose trait generated code reaches as `k.xam`.
    Xam,
    /// A library with no kernel trait in the runtime, by its file name.
    Other(String),
}

impl Library {
    /// The library with the file name the XEX gives it.
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "xboxkrnl.exe" => Library::Xboxkrnl,
            "xam.xex" => Library::Xam,
            _ => Library::Other(name.to_owned()),
        }
    }

    /// The field of `Kernels` that holds the library's trait, if it has one.
    fn field(&self) -> Option<&'static str> {
        match self {
            Library::Xboxkrnl => Some("krnl"),
            Library::Xam => Some("xam"),
            Library::Other(_) => None,
        }
    }

    /// The file name of the library.
    fn file_name(&self) -> &str {
        match self {
            Library::Xboxkrnl => "xboxkrnl.exe",
            Library::Xam => "xam.xex",
            Library::Other(name) => name,
        }
    }
}

/// A function or variable the module imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The library it comes from.
    pub library: Library,
    /// Its ordinal in the library.
    pub ordinal: u16,
    /// Its name, if the ordinal table of the library has the ordinal.
    pub name: Option<String>,
    /// Whether it is a function, as the ordinal table says; otherwise a variable.
    pub function: bool,
    /// The guest address of the word the loader fills in.
    pub slot: Option<u32>,
    /// The guest address of the thunk that calls the function, which functions have.
    pub thunk: Option<u32>,
}

impl Import {
    /// The method of the library's trait that stands for the import, if it has one: only a
    /// function with a name has.
    fn method(&self) -> Option<&str> {
        let name = self.name.as_deref().filter(|name| is_identifier(name))?;
        self.function.then_some(name)
    }

    /// The statement that calls the import, with the context, the memory and the kernels.
    pub(crate) fn call(&self) -> String {
        match (self.library.field(), self.method()) {
            (Some(field), Some(method)) => format!("k.{field}.{method}(ctx, mem, k);"),
            (Some(field), None) => {
                format!("k.{field}.unnamed_import({}, ctx, mem, k);", self.ordinal)
            }
            (None, _) => {
                let message = format!(
                    "import {} of {} has no kernel trait",
                    self.ordinal,
                    self.library.file_name()
                );
                format!("panic!(\"{{}}\", {message:?});")
            }
        }
    }

    /// The import as a doc comment names it.
    fn describe(&self) -> String {
        let name = self.name.as_deref().unwrap_or("an export with no name");
        format!(
            "`{name}`, ordinal {} of `{}`",
            self.ordinal,
            self.library.file_name()
        )
    }

    /// The statement of `load` that fills the slot, if the import has one that can be filled.
    fn fill_slot(&self) -> Option<String> {
        let slot = self.slot?;
        if let Some(thunk) = self.thunk {
            return Some(format!(
                "mem.write_u32({slot:#010x}, {thunk:#010x}); // {}",
                self.name.as_deref().unwrap_or("unnamed")
            ));
        }
        let field = self.library.field()?;
        let name = self.name.as_deref()?;
        (!self.function)
            .then(|| format!("mem.write_u32({slot:#010x}, k.{field}.resolve_variable({name:?}));"))
    }
}

/// Returns whether `name` can be a Rust identifier, as every name of the ordinal tables can.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The name of the function of `imports.rs` for the thunk at `addr`.
pub fn thunk_name(addr: u32) -> String {
    format!("thunk_{addr:08x}")
}

/// The text of the root crate's `imports.rs`.
pub(crate) fn imports_file(imports: &[Import]) -> String {
    let mut text = String::from(
        "//! Imports: a function per thunk, which the table registers at the thunk's address, and\n\
         //! `load`, which fills the import slots of the image.\n\n\
         use ferrum_runtime::{GuestFn, Kernels, Memory, PpcContext};\n\n",
    );
    let thunks: Vec<(u32, &Import)> = imports
        .iter()
        .filter_map(|import| import.thunk.map(|thunk| (thunk, import)))
        .collect();
    for &(thunk, import) in &thunks {
        let _ = writeln!(text, "/// {}.", import.describe());
        let _ = writeln!(
            text,
            "pub fn {}(ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {{\n    {}\n}}\n",
            thunk_name(thunk),
            import.call()
        );
    }
    text.push_str("/// The thunks, as address and function, for the table.\n");
    let _ = writeln!(
        text,
        "pub static THUNKS: [(u32, GuestFn); {}] = [",
        thunks.len()
    );
    for &(thunk, _) in &thunks {
        let _ = writeln!(text, "    ({thunk:#010x}, {}),", thunk_name(thunk));
    }
    text.push_str("];\n\n");
    text.push_str(
        "/// Writes every import slot of the image in `mem`: the address of its thunk for a function,\n\
         /// so that a call through the slot reaches the import, and the address the kernel gives\n\
         /// for a variable. The port calls it after loading the image and before guest code runs.\n\
         pub fn load(mem: &Memory, k: &Kernels<'_>) {\n",
    );
    for line in imports.iter().filter_map(Import::fill_slot) {
        let _ = writeln!(text, "    {line}");
    }
    text.push_str("    let _ = (mem, k);\n}\n");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn import(library: Library, name: Option<&str>, function: bool) -> Import {
        Import {
            library,
            ordinal: 7,
            name: name.map(str::to_owned),
            function,
            slot: Some(0x8200_0100),
            thunk: function.then_some(0x8260_0000),
        }
    }

    #[test]
    fn a_call_names_the_method_of_the_library_or_its_ordinal() {
        let call = |library, name, function| import(library, name, function).call();
        assert_eq!(
            call(Library::Xboxkrnl, Some("NtClose"), true),
            "k.krnl.NtClose(ctx, mem, k);"
        );
        assert_eq!(
            call(Library::Xam, Some("XamInputGetState"), true),
            "k.xam.XamInputGetState(ctx, mem, k);"
        );
        assert_eq!(
            call(Library::Xam, None, true),
            "k.xam.unnamed_import(7, ctx, mem, k);"
        );
        // A thunk whose ordinal the table calls a variable has no method either.
        assert_eq!(
            call(Library::Xboxkrnl, Some("XboxHardwareInfo"), false),
            "k.krnl.unnamed_import(7, ctx, mem, k);"
        );
        assert_eq!(
            call(Library::Other("xbdm.xex".into()), Some("DmGo"), true),
            "panic!(\"{}\", \"import 7 of xbdm.xex has no kernel trait\");"
        );
    }

    #[test]
    fn libraries_come_from_their_file_names() {
        assert_eq!(Library::from_name("xboxkrnl.exe"), Library::Xboxkrnl);
        assert_eq!(Library::from_name("XAM.XEX"), Library::Xam);
        assert_eq!(
            Library::from_name("xbdm.xex"),
            Library::Other("xbdm.xex".into())
        );
    }

    #[test]
    fn imports_rs_lists_the_thunks_and_fills_the_slots() {
        let imports = [
            import(Library::Xboxkrnl, Some("NtClose"), true),
            Import {
                slot: Some(0x8200_0104),
                thunk: None,
                ..import(Library::Xboxkrnl, Some("XboxHardwareInfo"), false)
            },
            Import {
                slot: Some(0x8200_0108),
                thunk: None,
                ..import(Library::Xboxkrnl, None, false)
            },
        ];
        let text = imports_file(&imports);
        assert!(
            text.contains(
                "pub fn thunk_82600000(ctx: &mut PpcContext, mem: &Memory, k: &Kernels<'_>) {\n    \
                 k.krnl.NtClose(ctx, mem, k);\n}"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "pub static THUNKS: [(u32, GuestFn); 1] = [\n    (0x82600000, thunk_82600000),\n];"
            ),
            "{text}"
        );
        assert!(
            text.contains("    mem.write_u32(0x82000100, 0x82600000); // NtClose\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "    mem.write_u32(0x82000104, k.krnl.resolve_variable(\"XboxHardwareInfo\"));\n"
            ),
            "{text}"
        );
        assert!(
            !text.contains("0x82000108"),
            "an unnamed variable keeps its slot: {text}"
        );
    }
}
