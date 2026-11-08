// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! XEX2 parser: turns an Xbox 360 executable into an in-memory PE image.
//!
//! Covers the XEX2 headers, AES-128-CBC decryption, LZX decompression, PE sections, `.pdata`,
//! exports, and the ordinal-to-name resolution of `xboxkrnl` and `xam` imports.
//!
//! The entry point is [`Xex::parse`]. Fatal problems come back as an [`Error`] naming the offset
//! and the field; problems that do not stop the file from being used are listed in
//! [`Xex::warnings`].
//!
//! The ordinal tables under `tables/xenia/` come from the Xenia project and are licensed under
//! BSD 3-Clause. See `tables/xenia/README.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
mod error;
mod exports;
pub mod header;
mod image;
mod imports;
mod lzx;
pub mod ordinals;
pub mod payload;
mod pe;
mod reader;

#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;

pub use error::{Error, ErrorKind, Location, Result};
pub use exports::Export;
pub use header::Header;
pub use image::{Image, Warning, Xex};
pub use imports::{Import, ImportLibrary};
pub use ordinals::ImportKind;
pub use pe::{DataDirectory, PeHeaders, RuntimeFunction, Section};

#[cfg(test)]
mod robustness_tests;
#[cfg(test)]
mod tests;
