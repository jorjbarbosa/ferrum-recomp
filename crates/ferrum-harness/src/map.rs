// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The `.map` files: the symbols `nm` lists for a test file, and the functions they make.
//!
//! Shared with the build script through `#[path]`, so it uses nothing outside the standard library.

/// A symbol of a `.map` file: its offset in the `.bin`, its type letter and its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Offset from the start of the `.bin`.
    pub offset: u32,
    /// The type letter `nm` prints, `t` for a local text symbol.
    pub kind: char,
    /// The name.
    pub name: String,
}

/// A test function: its symbol, and its range in the `.bin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestFunction {
    /// The symbol, `test_` and the case name.
    pub name: String,
    /// Offset from the start of the `.bin`.
    pub offset: u32,
    /// Size in bytes, up to the next test symbol or the end of the `.bin`.
    pub size: u32,
}

/// Parses the lines of a `.map` file, `00000010 t test_add2`.
pub fn parse_map(text: &str) -> Result<Vec<Symbol>, String> {
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut parts = line.split(' ');
            let (Some(offset), Some(kind), Some(name), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(format!("not a symbol line: {line:?}"));
            };
            let offset = u32::from_str_radix(offset, 16).map_err(|e| format!("{line:?}: {e}"))?;
            let mut kind_chars = kind.chars();
            let (Some(kind), None) = (kind_chars.next(), kind_chars.next()) else {
                return Err(format!("not a symbol type: {line:?}"));
            };
            Ok(Symbol {
                offset,
                kind,
                name: name.to_owned(),
            })
        })
        .collect()
}

/// The test functions of a file: one per `t test_` symbol, as in Xenia's harness, each up to the
/// next one or the end of the `.bin`. Other symbols are labels inside a test.
pub fn test_functions(symbols: &[Symbol], bin_len: usize) -> Result<Vec<TestFunction>, String> {
    let mut tests: Vec<&Symbol> = symbols
        .iter()
        .filter(|symbol| symbol.kind == 't' && symbol.name.starts_with("test_"))
        .collect();
    tests.sort_by_key(|symbol| symbol.offset);
    let end = u32::try_from(bin_len).map_err(|_| "a .bin over 4 GiB".to_owned())?;
    let mut functions = Vec::with_capacity(tests.len());
    for (index, symbol) in tests.iter().enumerate() {
        let next = tests.get(index + 1).map_or(end, |next| next.offset);
        if next <= symbol.offset || next > end {
            return Err(format!("{} has no instructions", symbol.name));
        }
        functions.push(TestFunction {
            name: symbol.name.clone(),
            offset: symbol.offset,
            size: next - symbol.offset,
        });
    }
    Ok(functions)
}
