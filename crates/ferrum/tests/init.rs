// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Runs `ferrum init` as a process and checks the port it writes: `ferrum recomp` runs on the
//! config it wrote, and Cargo checks the port against the generated code.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{code, scratch};

fn init(dir: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferrum"))
        .arg("init")
        .arg(dir)
        .args(extra)
        .output()
        .unwrap()
}

fn read(path: PathBuf) -> String {
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn init_writes_a_port_that_recompiles_and_checks() {
    let dir = scratch("init-port");
    let port = dir.join("port");
    let output = init(&port, &["--name", "sample"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ferrum recomp config/sample.toml"),
        "{stdout}"
    );
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        ".gitignore",
        "config/sample.toml",
        "crates/sample/Cargo.toml",
        "crates/sample/src/main.rs",
    ] {
        assert!(port.join(path).is_file(), "{path}");
    }
    assert!(port.join("game").is_dir());

    // The config needs nothing more to run, and the output goes inside the port's workspace,
    // which excludes it.
    fs::write(port.join("game/default.xex"), code()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ferrum"))
        .arg("recomp")
        .arg(port.join("config/sample.toml"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(port.join("generated/sample-ppc/Cargo.toml").is_file());

    // The port builds against the generated code, offline, with the versions of the copied lock.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["check", "--offline", "--quiet", "-p", "sample"])
        .current_dir(&port)
        .env(
            "CARGO_TARGET_DIR",
            Path::new(env!("CARGO_TARGET_TMPDIR")).join("init-check"),
        )
        .output()
        .unwrap();
    let errors = stderr(&output);
    assert!(output.status.success(), "{errors}");
    assert!(!errors.contains("warning"), "{errors}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn init_keeps_what_the_directory_already_holds() {
    let dir = scratch("init-existing");
    let port = dir.join("my-port");
    fs::create_dir_all(&port).unwrap();
    fs::write(port.join(".gitignore"), "/target/\nnotes.txt").unwrap();
    fs::write(port.join("Cargo.lock"), "# the port's own lock\n").unwrap();
    let output = init(&port, &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    // The name comes from the directory.
    let config = read(port.join("config/my-port.toml"));
    assert!(config.contains(r#"crate_name = "my-port-ppc""#), "{config}");
    assert!(port.join("crates/my-port/src/main.rs").is_file());
    // The .gitignore gets only the patterns it lacks, and the lock stays.
    assert_eq!(
        read(port.join(".gitignore")),
        "/target/\nnotes.txt\n/game/\n/generated/\n"
    );
    assert_eq!(read(port.join("Cargo.lock")), "# the port's own lock\n");

    // A second run refuses to overwrite the skeleton, and changes nothing.
    let main = port.join("crates/my-port/src/main.rs");
    fs::write(&main, "// mine\n").unwrap();
    let output = init(&port, &[]);
    assert!(!output.status.success());
    let errors = stderr(&output);
    assert!(errors.contains("already holds Cargo.toml"), "{errors}");
    assert!(errors.contains("--force"), "{errors}");
    assert_eq!(read(main.clone()), "// mine\n");
    // --force writes it again.
    let output = init(&port, &["--force"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_ne!(read(main), "// mine\n");

    // A name that cannot name a crate is refused.
    let output = init(&dir.join("other"), &["--name", "1st"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot name a port"));
    fs::remove_dir_all(&dir).unwrap();
}
