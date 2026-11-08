// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Writes the output workspace of a synthetic program, as `ferrum recomp` will write a game's.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use ferrum_analysis::{Code, find_save_restore};
use ferrum_codegen::{Layout, Program, write_workspace};

use crate::synth;

/// What to generate.
#[derive(Debug, Clone, clap::Args)]
pub struct Options {
    /// Where to write the workspace. It has to be outside this repository.
    #[arg(long)]
    pub out: PathBuf,
    /// How many functions to generate.
    #[arg(long, default_value_t = 50_000)]
    pub functions: usize,
    /// How many functions each crate holds (`functions_per_crate`).
    #[arg(long, default_value_t = ferrum_codegen::DEFAULT_FUNCTIONS_PER_CRATE)]
    pub per_crate: usize,
    /// The seed of the generator.
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    /// The name of the root crate; the others are `<name>-NNN`.
    #[arg(long, default_value = "scale-ppc")]
    pub name: String,
}

/// What [`write`] generated.
#[derive(Debug, Clone)]
pub struct Summary {
    /// Guest functions.
    pub functions: usize,
    /// Guest instructions in them.
    pub insns: u64,
    /// Crates of the workspace, the root crate included.
    pub crates: usize,
    /// Bytes of generated Rust.
    pub bytes: u64,
    /// Lines of generated Rust.
    pub lines: u64,
    /// How long building the program and generating its Rust took.
    pub generation: Duration,
    /// Files written, as opposed to left alone because they were the same.
    pub written: usize,
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} functions, {} instructions, {} crates, {:.1} MB of Rust in {} lines, \
             generated in {:.1} s, {} files written",
            self.functions,
            self.insns,
            self.crates,
            self.bytes as f64 / 1e6,
            self.lines,
            self.generation.as_secs_f64(),
            self.written
        )
    }
}

/// The repository this binary was built from.
pub fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives in crates/ferrum-scale")
        .to_path_buf()
}

/// Generates the program of `options` and writes its workspace, with a copy of the repository's
/// `Cargo.lock` if the workspace has none yet.
pub fn write(options: &Options) -> Result<Summary> {
    check_outside_repository(&options.out)?;
    let start = Instant::now();
    let program = synth::generate(options.seed, options.functions);
    let bytes = program.bytes();
    let code = Code::new(synth::BASE, &bytes);
    let routines = find_save_restore(&code);
    let layout = Layout {
        name: options.name.clone(),
        functions_per_crate: options.per_crate,
        runtime: repository().join("crates").join("ferrum-runtime"),
    };
    let files = Program::new(code, program.functions.iter().copied(), &routines)
        .workspace(&layout)
        .context("cannot generate the workspace")?;
    let generation = start.elapsed();
    let written = write_workspace(&options.out, &files)
        .with_context(|| format!("cannot write {}", options.out.display()))?;
    let lock = options.out.join("Cargo.lock");
    if !lock.exists() {
        fs::copy(repository().join("Cargo.lock"), &lock)
            .with_context(|| format!("cannot copy Cargo.lock to {}", lock.display()))?;
    }
    let rust = files.iter().filter(|file| file.path.ends_with(".rs"));
    Ok(Summary {
        functions: program.functions.len(),
        insns: program.function_insns(),
        crates: files
            .iter()
            .filter(|file| file.path.ends_with("/Cargo.toml"))
            .count(),
        bytes: rust.clone().map(|file| file.text.len() as u64).sum(),
        lines: rust.map(|file| file.text.lines().count() as u64).sum(),
        generation,
        written,
    })
}

/// Fails if `out` is inside the repository or holds it: Cargo gets confused by a workspace nested
/// in another.
fn check_outside_repository(out: &Path) -> Result<()> {
    fs::create_dir_all(out).with_context(|| format!("cannot create {}", out.display()))?;
    let out = fs::canonicalize(out)?;
    let repository = fs::canonicalize(repository())?;
    if out.starts_with(&repository) || repository.starts_with(&out) {
        bail!(
            "{} is inside the repository or holds it; write the workspace elsewhere",
            out.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measure::cargo;

    #[test]
    fn a_small_workspace_passes_cargo_check_without_warnings() {
        let out = std::env::temp_dir().join(format!("ferrum-scale-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out);
        let options = Options {
            out: out.clone(),
            functions: 300,
            per_crate: 100,
            seed: 1,
            name: "scale-ppc".to_owned(),
        };
        let summary = write(&options).unwrap();
        assert_eq!(summary.functions, 300);
        assert_eq!(summary.crates, 4);
        // A target directory of its own, kept between runs so that the dependencies stay built.
        let target = repository().join("target").join("ferrum-scale-test");
        let output = cargo(&out, &target, false)
            .args(["check", "--offline", "--message-format", "short"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(!stderr.contains("warning"), "{stderr}");
        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn the_workspace_has_to_be_outside_the_repository() {
        let inside = repository().join("target").join("ferrum-scale-inside");
        let parent = repository().parent().unwrap().to_path_buf();
        for out in [inside.clone(), repository(), parent] {
            let options = Options {
                out: out.clone(),
                functions: 1,
                per_crate: 1,
                seed: 1,
                name: "scale-ppc".to_owned(),
            };
            let error = write(&options).unwrap_err().to_string();
            assert!(error.contains("inside the repository"), "{error}");
        }
        assert!(
            fs::read_dir(&inside).unwrap().next().is_none(),
            "nothing written"
        );
        fs::remove_dir(&inside).unwrap();
    }
}
