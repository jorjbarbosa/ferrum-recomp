// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! `manifest.toml`: the group of every test file, and the cases expected to fail.
//!
//! Shared with the build script through `#[path]`, so it uses only `serde` and `toml`.

use std::collections::BTreeMap;

use serde::Deserialize;

/// What a test file exercises, which decides the acceptance test that runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Group {
    /// Integer, branch, load and store instructions.
    Integer,
    /// Floating-point instructions.
    Float,
    /// VMX and VMX128 instructions.
    Vector,
    /// Whole programs that need function discovery and jump tables.
    Discovery,
    /// Not a test.
    #[serde(rename = "none")]
    NotATest,
}

impl Group {
    /// Whether the files of this group are tests, which the build script compiles.
    pub fn is_test(self) -> bool {
        self != Group::NotATest
    }

    /// Whether the functions of a file come from function discovery, with the test symbols as
    /// entries, instead of one function per test symbol.
    pub fn discovers(self) -> bool {
        self == Group::Discovery
    }
}

/// A case that fails on purpose, and why.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    /// The case, `<directory>/<stem>:<symbol>`.
    pub case: String,
    /// Why it fails.
    pub reason: String,
}

/// A jump table whose bound check the analysis cannot see, with the count of entries it would
/// have given, as `[analysis] jump_tables` does for a game.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JumpTableCount {
    /// The file, `<directory>/<stem>`.
    pub file: String,
    /// Offset of the `bctr` in the `.bin`.
    pub bctr: u32,
    /// The number of entries.
    pub entries: u32,
    /// Why the analysis cannot find the count.
    pub reason: String,
}

/// The parsed manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Every `.s` file, as `<directory>/<stem>` under `tests/`, with its group.
    pub files: BTreeMap<String, Group>,
    /// The cases expected to fail. Each belongs to the acceptance test of its file's group.
    #[serde(default, rename = "exclusion")]
    pub exclusions: Vec<Exclusion>,
    /// The counts of jump tables the analysis cannot bound.
    #[serde(default, rename = "jump_table")]
    pub jump_tables: Vec<JumpTableCount>,
}

impl Manifest {
    /// Parses the text of `manifest.toml`. TOML rejects a repeated key, so no file can have two
    /// groups.
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|error| error.to_string())
    }
}
