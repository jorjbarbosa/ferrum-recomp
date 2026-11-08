// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Errors of the analysis.

/// Why a function could not be analyzed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The function's entry is not a 4-aligned address, or its range holds no instruction.
    #[error("function at {function:#010x} with size {size:#x} holds no aligned instruction")]
    BadFunction {
        /// Address of the function.
        function: u32,
        /// Size of the function in bytes.
        size: u32,
    },
    /// A path of the function reaches an address the code does not hold.
    #[error("function {function:#010x} reaches {addr:#010x}, outside the code")]
    OutsideCode {
        /// Address of the function.
        function: u32,
        /// The address outside the code.
        addr: u32,
    },
    /// A path of the function reaches a word that is no instruction.
    #[error("function {function:#010x} reaches the undecodable word {word:#010x} at {addr:#010x}")]
    Undecodable {
        /// Address of the function.
        function: u32,
        /// Address of the word.
        addr: u32,
        /// The word.
        word: u32,
    },
}
