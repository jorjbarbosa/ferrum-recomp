// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Runs `ferrum recomp` as a process over a synthetic XEX file and checks the workspace it writes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ferrum_xex::fixtures::sample::{SampleLayout, THUNKS_OFFSET};

/// The size of `.text` in the sample.
const TEXT_SIZE: usize = 0x800;

/// A sample whose `.text` holds the given words at the given offsets, zero elsewhere apart from
/// the import thunks, so that the sweep of the gaps finds nothing else.
fn sample(code: &[(usize, &[u32])]) -> Vec<u8> {
    let layout = SampleLayout::default();
    let mut builder = layout.builder();
    let text = (layout.text() - layout.base) as usize;
    let thunks = text + THUNKS_OFFSET as usize;
    builder.image[text..thunks].fill(0);
    // Three thunks of 16 bytes, for the three imported functions of the sample.
    builder.image[thunks + 0x30..text + TEXT_SIZE].fill(0);
    for &(offset, words) in code {
        for (index, word) in words.iter().enumerate() {
            let at = text + offset + 4 * index;
            builder.image[at..at + 4].copy_from_slice(&word.to_be_bytes());
        }
    }
    builder.build().bytes
}

/// The code of the test: the three `.pdata` functions of the sample, a call to the first thunk
/// (`ExCreateThread`), and one function that only the sweep finds.
fn code() -> Vec<u8> {
    sample(&[
        // .text+0x00: bl .text+0x10; bl .text+0x400; li r3,0; blr
        (0x00, &[0x4800_0011, 0x4800_03FD, 0x3860_0000, 0x4E80_0020]),
        // .text+0x10: li r3,1; blr
        (0x10, &[0x3860_0001, 0x4E80_0020]),
        // .text+0x30: li r3,2; blr
        (0x30, &[0x3860_0002, 0x4E80_0020]),
        // .text+0x40: li r3,3; blr
        (0x40, &[0x3860_0003, 0x4E80_0020]),
    ])
}

/// A fresh directory outside every Cargo workspace.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ferrum-recomp-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_config(dir: &Path, out: &str, extra: &str) -> PathBuf {
    fs::write(dir.join("game.xex"), code()).unwrap();
    let config = dir.join("config.toml");
    let text =
        format!("[main]\nxex = \"game.xex\"\nout = {out:?}\ncrate_name = \"sample-ppc\"\n{extra}");
    fs::write(&config, text).unwrap();
    config
}

fn recomp(config: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferrum"))
        .arg("recomp")
        .arg(config)
        .args(extra)
        .output()
        .unwrap()
}

fn read(path: PathBuf) -> String {
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn recomp_writes_the_workspace_of_the_sample() {
    let dir = scratch("sample");
    let config = write_config(&dir, "out", "");
    let output = recomp(&config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("functions: 4 ("), "{stdout}");
    assert!(stdout.contains("wrote "), "{stdout}");

    let out = dir.join("out");
    assert!(out.join("Cargo.toml").is_file());
    assert!(out.join("Cargo.lock").is_file(), "the lock is copied");
    let part = read(out.join("sample-ppc-000/src/lib.rs"));
    for function in [
        "sub_82010000",
        "sub_82010010",
        "sub_82010030",
        "sub_82010040",
    ] {
        assert!(
            part.contains(&format!("pub fn {function}(")),
            "{function}\n{part}"
        );
    }
    assert!(
        part.contains("k.krnl.ExCreateThread(ctx, mem, k);"),
        "{part}"
    );
    let imports = read(out.join("sample-ppc/src/imports.rs"));
    assert!(
        imports.contains("k.xam.XamInputGetState(ctx, mem, k);"),
        "{imports}"
    );
    assert!(
        imports.contains("k.krnl.resolve_variable(\"XboxHardwareInfo\")"),
        "{imports}"
    );
    let table = read(out.join("sample-ppc/src/table.rs"));
    assert!(table.contains("&crate::imports::THUNKS,"), "{table}");
    assert!(out.join("sample-ppc/src/hooks.rs").is_file());

    // A second run with the same input rewrites nothing.
    let output = recomp(&config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("wrote 0 of "), "{stdout}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn recomp_refuses_an_output_inside_a_cargo_workspace() {
    let dir = scratch("nested");
    fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let config = write_config(&dir, "out", "");
    let output = recomp(&config, &[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lies inside the Cargo workspace"),
        "{stderr}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn recomp_reports_config_and_hook_errors() {
    let dir = scratch("errors");
    let config = write_config(&dir, "out", "[optimizations]\nlocals = true\n");
    let output = recomp(&config, &[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not implemented"), "{stderr}");

    // A hook on an instruction of a path is fine; one on a word that no path reaches, inside the
    // second .pdata function, fails the run.
    let config = write_config(
        &dir,
        "out",
        "[hooks]\nmidasm = [ { addr = 0x82010008, name = \"live\" } ]\n",
    );
    let output = recomp(&config, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = write_config(
        &dir,
        "out",
        "[hooks]\nmidasm = [ { addr = 0x82010018, name = \"dead\" } ]\n",
    );
    let output = recomp(&config, &[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no path of a function reaches it"),
        "{stderr}"
    );
    fs::remove_dir_all(&dir).unwrap();
}
