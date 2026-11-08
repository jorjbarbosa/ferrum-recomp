// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Runs the Xenia PPC suites under `tests/` through `ferrum-codegen` and `ferrum-runtime`.
//!
//! The build script reads `manifest.toml` and generates Rust for every test file it lists and for
//! the [`synthetic`] programs, which cover what the suites leave out. [`generated`] holds that
//! output; `tests/suite.rs` runs it with [`runner::Harness`], comparing the registers and memory
//! the [`annotations`] name.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod annotations;
pub mod manifest;
pub mod map;
pub mod runner;
pub mod synthetic;
pub mod values;

use std::path::{Path, PathBuf};

use ferrum_runtime::GuestFn;

use crate::manifest::Group;

/// The code the build script generated: a module per test file and per synthetic program,
/// [`generated::FILES`] and [`generated::SYNTHETIC`]. It is machine-written, so lints about style
/// do not apply; `unsafe` stays forbidden.
#[allow(missing_docs, unused, clippy::all, clippy::pedantic)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/suite.rs"));
}

/// What the build script made of one test file.
#[derive(Debug, Clone, Copy)]
pub struct GeneratedFile {
    /// The file, as `<directory>/<stem>` under `tests/`.
    pub name: &'static str,
    /// Its group in the manifest.
    pub group: Group,
    /// Its generated functions, or why there are none.
    pub code: Generated,
}

/// The outcome of generating one test file.
#[derive(Debug, Clone, Copy)]
pub enum Generated {
    /// The functions, one entry per word of the `.bin` from [`runner::CODE_BASE`]: the function
    /// that starts there, if any.
    Code(&'static [Option<GuestFn>]),
    /// A file that codegen rejected, with its error.
    Failed(&'static str),
}

/// The `tests/` directory of the repository.
pub fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests")
}
