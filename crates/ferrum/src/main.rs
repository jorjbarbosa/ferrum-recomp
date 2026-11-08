// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Command-line interface of the ferrum static recompiler.
//!
//! `recomp` generates the Rust workspace of a game from its XEX and a TOML config; `dump` and
//! `disasm` look into a XEX.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod disasm;
mod dump;
mod recomp;

use std::num::ParseIntError;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Static recompiler from Xbox 360 PowerPC executables (XEX2) to Rust.
#[derive(Debug, Parser)]
#[command(name = "ferrum", version)]
struct Cli {
    /// The operation to run.
    #[command(subcommand)]
    command: Command,
}

/// Operations offered by the CLI.
#[derive(Debug, Subcommand)]
enum Command {
    /// Generate the Rust output workspace described by a TOML config.
    Recomp {
        /// Path to the recompilation config.
        config: PathBuf,
        /// Treat warnings as errors.
        #[arg(long)]
        strict: bool,
    },
    /// Print the headers, sections, .pdata and imports of a XEX file.
    Dump {
        /// Path to the XEX file.
        xex: PathBuf,
        /// Treat warnings as errors.
        #[arg(long)]
        strict: bool,
    },
    /// Disassemble a XEX file in objdump syntax, starting at a guest address.
    ///
    /// Without --count, the listing stops at the end of the .pdata function at the address. If no
    /// function holds it, it stops at the next function or at the end of the section.
    Disasm {
        /// Path to the XEX file.
        xex: PathBuf,
        /// Guest address in hexadecimal, with or without a 0x prefix.
        #[arg(long, value_parser = parse_addr)]
        addr: u32,
        /// How many words to list, stopping early at the end of the section.
        #[arg(long)]
        count: Option<u32>,
    },
}

/// Parses a guest address written in hexadecimal, with or without a `0x` prefix.
fn parse_addr(text: &str) -> Result<u32, ParseIntError> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u32::from_str_radix(digits, 16)
}

/// Runs the selected subcommand.
fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Recomp { config, strict } => recomp::run(&config, strict),
        Command::Dump { xex, strict } => dump::run(&xex, strict),
        Command::Disasm { xex, addr, count } => disasm::run(&xex, addr, count),
    }
}

fn main() -> Result<()> {
    run(Cli::parse())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parse_addr_accepts_hex_with_or_without_prefix() {
        for text in ["0x82001000", "0X82001000", "82001000"] {
            assert_eq!(parse_addr(text), Ok(0x8200_1000), "input: {text:?}");
        }
    }

    #[test]
    fn parse_addr_rejects_invalid_values() {
        for text in ["", "0x", "not-hex", "0x100000000"] {
            assert!(parse_addr(text).is_err(), "input: {text:?}");
        }
    }

    #[test]
    fn disasm_requires_addr() {
        assert!(Cli::try_parse_from(["ferrum", "disasm", "game.xex"]).is_err());
    }

    #[test]
    fn recomp_takes_a_config_and_strict() {
        let cli = Cli::try_parse_from(["ferrum", "recomp", "game.toml", "--strict"]).unwrap();
        assert!(matches!(cli.command, Command::Recomp { strict: true, .. }));
        assert!(Cli::try_parse_from(["ferrum", "recomp"]).is_err());
        let cli = Cli::try_parse_from(["ferrum", "recomp", "no-such-config.toml"]).unwrap();
        let message = format!("{:#}", run(cli).unwrap_err());
        assert!(message.contains("cannot read"), "message: {message}");
    }

    #[test]
    fn disasm_takes_a_count() {
        let args = [
            "ferrum", "disasm", "game.xex", "--addr", "0x10", "--count", "3",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(matches!(
            cli.command,
            Command::Disasm {
                addr: 0x10,
                count: Some(3),
                ..
            }
        ));
    }
}
