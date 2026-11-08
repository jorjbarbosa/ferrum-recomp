// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Synthetic workload that measures how long Cargo takes over generated code for a given number
//! of functions per crate, which settles the default of `functions_per_crate`.
//!
//! Builds a program of guest functions with `Insn::encode` (see `synth`), generates it with
//! `ferrum-codegen` as an output workspace, and writes it outside the repository. `measure` then
//! times `cargo check` over it. Nothing here comes from a game, and nothing runs in CI at full
//! size: a test generates 300 functions and checks them with Cargo.

#![forbid(unsafe_code)]

mod measure;
mod output;
mod rng;
mod synth;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

/// Synthetic workload that measures `cargo check` over a generated output workspace.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Writes the output workspace of a synthetic program.
    Generate(output::Options),
    /// Writes the workspace, then times Cargo over it.
    Measure {
        #[command(flatten)]
        options: output::Options,
        #[command(flatten)]
        protocol: measure::Protocol,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate(options) => {
            let options = absolute(options)?;
            println!("{}", output::write(&options)?);
        }
        Command::Measure { options, protocol } => {
            let options = absolute(options)?;
            let summary = output::write(&options)?;
            println!("{summary}");
            measure::run(&options, &summary, &protocol)?;
        }
    }
    Ok(())
}

/// The options with an absolute output directory, since Cargo runs from inside it.
fn absolute(mut options: output::Options) -> Result<output::Options> {
    options.out = std::path::absolute(&options.out)
        .with_context(|| format!("cannot resolve {}", options.out.display()))?;
    Ok(options)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
        let cli =
            Cli::try_parse_from(["ferrum-scale", "measure", "--out", "x", "--build"]).unwrap();
        let Command::Measure { options, protocol } = cli.command else {
            panic!("not measure");
        };
        assert_eq!(
            (options.functions, options.per_crate, options.seed),
            (50_000, 100, 1)
        );
        assert_eq!(options.name, "scale-ppc");
        assert!(protocol.build && !protocol.incremental);
        assert_eq!(protocol.runs, 3);
    }
}
