// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Runs `ferrum recomp` as a process over a synthetic XEX file and checks the workspace it writes.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{code, sample, scratch, text};
use ferrum_decoder::{Gpr, Insn};

/// `blr`.
const BLR: u32 = 0x4E80_0020;

/// A sample whose first function calls a `setjmp` at `.text+0x100` and a `longjmp` at
/// `.text+0x200`, which use a buffer with r1 at 0x10, r14 to r31 from 0x20 and LR at 0xB0.
fn non_local_code() -> Vec<u8> {
    let slot = |reg: u8| 0x20 + 8 * (i16::from(reg) - 14);
    let mut setjmp = vec![Insn::Mfspr { rt: Gpr(0), spr: 8 }.encode()];
    setjmp.extend((14..32).map(|reg| {
        Insn::Std {
            rs: Gpr(reg),
            ds: slot(reg),
            ra: Gpr(3),
        }
        .encode()
    }));
    setjmp.extend([
        Insn::Stw {
            rs: Gpr(0),
            d: 0xB0,
            ra: Gpr(3),
        }
        .encode(),
        Insn::Std {
            rs: Gpr(1),
            ds: 0x10,
            ra: Gpr(3),
        }
        .encode(),
        0x3860_0000, // li r3,0
        BLR,
    ]);
    let mut longjmp = vec![0x7C67_1B78]; // mr r7,r3
    longjmp.extend((14..32).map(|reg| {
        Insn::Ld {
            rt: Gpr(reg),
            ds: slot(reg),
            ra: Gpr(7),
        }
        .encode()
    }));
    longjmp.extend([
        Insn::Lwz {
            rt: Gpr(5),
            d: 0xB0,
            ra: Gpr(7),
        }
        .encode(),
        0x7CA8_03A6, // mtlr r5
        Insn::Ld {
            rt: Gpr(1),
            ds: 0x10,
            ra: Gpr(7),
        }
        .encode(),
        0x7C83_2378, // mr r3,r4
        BLR,
    ]);
    sample(&[
        // .text+0x00: bl .text+0x100; bl .text+0x200; li r3,0; blr
        (0x00, &[0x4800_0101, 0x4800_01FD, 0x3860_0000, BLR]),
        (0x10, &[0x3860_0001, BLR]),
        (0x30, &[0x3860_0002, BLR]),
        (0x40, &[0x3860_0003, BLR]),
        (0x100, &setjmp),
        (0x200, &longjmp),
    ])
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

#[test]
fn recomp_finds_setjmp_and_longjmp_unless_the_config_names_them() {
    let dir = scratch("non-local");
    fs::write(dir.join("game.xex"), non_local_code()).unwrap();
    let config = dir.join("config.toml");
    let main = "[main]\nxex = \"game.xex\"\nout = \"out\"\ncrate_name = \"sample-ppc\"\n";
    let (setjmp, longjmp) = (text() + 0x100, text() + 0x200);

    fs::write(&config, main).unwrap();
    let output = recomp(&config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stdout.contains(&format!("setjmp: {setjmp:#010x} (found)")),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("longjmp: {longjmp:#010x} (found)")),
        "{stdout}"
    );
    // longjmp never returns, and neither does the first function, whose path ends in a call to it.
    assert!(stdout.contains("never return: 2"), "{stdout}");

    // A config that names another address wins, with a warning.
    let other = text() + 0x10;
    fs::write(&config, format!("{main}[analysis]\nsetjmp = {other:#x}\n")).unwrap();
    let output = recomp(&config, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stdout.contains(&format!("setjmp: {other:#010x} (config)")),
        "{stdout}"
    );
    assert!(
        stderr.contains(&format!(
            "[analysis] setjmp is {other:#010x}, but the code has the shape of setjmp at {setjmp:#010x}"
        )),
        "{stderr}"
    );
    fs::remove_dir_all(&dir).unwrap();
}
