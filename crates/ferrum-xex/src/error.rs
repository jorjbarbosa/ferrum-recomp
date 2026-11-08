// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Errors raised while parsing a XEX2 file.
//!
//! Every error carries the location and the field that caused it, so the type makes it impossible
//! to report a failure without saying where it happened.

use std::borrow::Cow;
use std::fmt;

/// Shorthand for results whose error is [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// A fatal problem found in a XEX2 file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{location}, field `{field}`: {kind}")]
pub struct Error {
    /// Where the problem is.
    pub location: Location,
    /// The name of the field that holds the bad data, such as `security_info.image_size`.
    pub field: Cow<'static, str>,
    /// What is wrong with the field.
    pub kind: ErrorKind,
}

/// A position in one of the two address spaces an error can refer to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// Byte offset from the start of the XEX file. Encryption does not move bytes, so this also
    /// holds for data that was decrypted before being parsed.
    File(u64),
    /// Byte offset from the start of the decrypted and decompressed image. Such a byte may have no
    /// single position in the file.
    Image(u64),
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::File(offset) => write!(f, "file offset {offset:#x}"),
            Location::Image(offset) => write!(f, "image offset {offset:#x}"),
        }
    }
}

/// The ways a field of a XEX2 file can be wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The data ends before the field does.
    #[error("truncated: needs {needed} bytes but only {available} are available")]
    Truncated {
        /// Bytes the field needs.
        needed: u64,
        /// Bytes present from the field's offset onwards.
        available: u64,
    },
    /// A signature does not have its fixed value.
    #[error("bad magic: expected {expected:#x}, found {found:#x}")]
    BadMagic {
        /// The value the format requires.
        expected: u32,
        /// The value in the file.
        found: u32,
    },
    /// A value breaks a rule of the format.
    #[error("invalid value {value:#x}: {reason}")]
    InvalidValue {
        /// The value in the file.
        value: u64,
        /// The rule it breaks.
        reason: &'static str,
    },
    /// A value is legal in the format but outside what this crate handles.
    #[error("unsupported value {value:#x}: {reason}")]
    Unsupported {
        /// The value in the file.
        value: u64,
        /// Why it is not handled.
        reason: &'static str,
    },
    /// A required optional header is absent.
    #[error("required optional header is missing")]
    Missing,
    /// A block of compressed data does not match the SHA-1 digest that precedes it.
    #[error("SHA-1 digest mismatch: the data is corrupt")]
    DigestMismatch,
    /// None of the known keys produces a plausible plaintext.
    #[error("no known key decrypts the image (tried retail and devkit), or its start is corrupt")]
    WrongKey,
    /// The LZX decoder rejected the compressed stream.
    #[error("corrupt LZX stream: {reason}")]
    CorruptLzx {
        /// The decoder's description of the failure.
        reason: String,
    },
}
