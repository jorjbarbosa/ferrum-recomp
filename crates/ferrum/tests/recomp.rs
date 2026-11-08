// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Runs `ferrum recomp` as a process over a synthetic XEX file and checks the workspace it writes.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{code, scratch};

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
fn recomp_writes_inside_a_cargo_workspace_only_if_it_excludes_the_output() {
    let dir = scratch("nested");
    let refused = |workspace: &str, out: &str| {
        fs::write(dir.join("Cargo.toml"), workspace).unwrap();
        let output = recomp(&write_config(&dir, out, ""), &[]);
        assert!(!output.status.success(), "{workspace}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("lies inside the Cargo workspace"),
            "{stderr}"
        );
        assert!(stderr.contains("list it under `exclude`"), "{stderr}");
    };
    let accepted = |workspace: &str, out: &str| {
        fs::write(dir.join("Cargo.toml"), workspace).unwrap();
        let output = recomp(&write_config(&dir, out, ""), &[]);
        assert!(
            output.status.success(),
            "{workspace}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(dir.join(out).join("Cargo.toml").is_file(), "{workspace}");
    };

    refused("[workspace]\nmembers = []\n", "out");
    // An entry that does not hold the output is no help: one that does not exist, a sibling, or
    // a directory inside the output.
    refused(
        "[workspace]\nmembers = []\nexclude = [\"missing\"]\n",
        "out",
    );
    fs::create_dir_all(dir.join("other")).unwrap();
    refused("[workspace]\nmembers = []\nexclude = [\"other\"]\n", "out");
    fs::create_dir_all(dir.join("out/inner")).unwrap();
    refused(
        "[workspace]\nmembers = []\nexclude = [\"out/inner\"]\n",
        "out",
    );
    accepted("[workspace]\nmembers = []\nexclude = [\"out\"]\n", "out");
    // An entry excludes everything under it, and may be written with a leading ./ or a trailing /.
    accepted(
        "[workspace]\nmembers = []\nexclude = [\"./generated/\"]\n",
        "generated/sample-ppc",
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
