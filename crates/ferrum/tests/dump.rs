// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Runs `ferrum dump` as a process over synthetic XEX files written to a temporary directory.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use ferrum_xex::fixtures::sample::{ImportSpec, LibrarySpec, SampleLayout};
use ferrum_xex::fixtures::{FixtureCompression, FixtureEncryption};

/// Writes a file for one test, and returns its path.
fn write_fixture(name: &str, bytes: &[u8]) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dump-fixtures");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

/// Runs `ferrum dump` with the given extra arguments.
fn dump(path: &PathBuf, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferrum"))
        .arg("dump")
        .arg(path)
        .args(extra)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

/// A sample whose payload is encrypted with the retail key and LZX compressed.
fn sample_bytes() -> Vec<u8> {
    let mut builder = SampleLayout::default().builder();
    builder.encryption = FixtureEncryption::Retail;
    builder.compression = FixtureCompression::LzxVerbatimBlocks;
    builder.build().bytes
}

#[test]
fn lists_headers_sections_pdata_and_imports() {
    let path = write_fixture("full.xex", &sample_bytes());
    let output = dump(&path, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);

    for expected in [
        "== XEX2 header ==",
        "module flags:  0x00000001 [\"title\"]",
        "original PE:   synthetic.pe",
        "version:       1.2.3456.78",
        "== Security info ==",
        "image size:    0x40000",
        "load address:  0x82000000",
        "page size:     0x10000",
        "== Optional headers (8) ==",
        "0x00010100 0x82010000 entry_point",
        "== Image ==",
        "base:          0x82000000",
        "entry point:   0x82010000",
        "encryption:    AES-128-CBC, retail key",
        "compression:   LZX, window 0x8000",
        "page digests:  ok",
        "== Memory pages (3 descriptors) ==",
        "0x82000000-0x82010000 read-only data",
        "0x82010000-0x82020000 code",
        "0x82020000-0x82040000 data",
        "== Sections (5) ==",
        ".rdata   0x82000400 0x82000900 0x00000500 0x00000400 0x00000600 0x40000040 r--  0x500",
        ".text    0x82010000 0x82010800 0x00000800 0x00000c00 0x00000800 0x60000020 r-x  0x800",
        ".data    0x82020000 0x82020200 0x00000200 0x00001400 0x00000200 0xc0000040 rw-  0x200",
        ".reloc   0x82040000 0x82041000 0x00001000 0x00001600 0x00001000 0x42000040 r--  0x0",
        "== TLS ==",
        "slots:         64",
        "== .pdata (3) ==",
        "0x82010000 0x00000010 2      32bit",
        "0x82010010 0x00000020 3      32bit,eh",
        "0x82010030 0x00000010 0      ",
        "== Imports (5) ==",
        "xboxkrnl.exe version 2.0.24.130 min 2.0.22.134 id 0x1234abcd (3 imports)",
        "  0x000d function slot=0x82020100 thunk=0x82010400 ExCreateThread",
        "  0x0059 variable slot=0x82020108 thunk=- KeDebugMonitorData",
        "  0x0156 variable slot=0x82020104 thunk=- XboxHardwareInfo",
        "xam.xex version 2.0.24.130 min 2.0.22.134 id 0x1234abcd (2 imports)",
        "  0x0191 function slot=0x8202010c thunk=0x82010410 XamInputGetState",
        "  0x02ca function slot=0x82020110 thunk=0x82010420 XamShowMessageBoxUI",
        "== Exports (2) ==",
        "1      0x82010000 <unnamed>",
        "3      0x82010010 <unnamed>",
    ] {
        let found = text.lines().any(|line| line == expected);
        assert!(found, "missing line {expected:?} in:\n{text}");
    }
}

#[test]
fn sections_come_in_a_fixed_order() {
    let path = write_fixture("order.xex", &sample_bytes());
    let text = stdout(&dump(&path, &[]));
    let positions: Vec<_> = [
        "== XEX2 header ==",
        "== Security info ==",
        "== Optional headers",
        "== Image ==",
        "== Memory pages",
        "== Sections",
        "== Resources",
        "== TLS ==",
        "== .pdata",
        "== Imports",
        "== Exports",
    ]
    .iter()
    .map(|title| text.find(title).unwrap())
    .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn an_invalid_file_fails_with_offset_and_field() {
    let path = write_fixture("invalid.xex", b"not a xex file at all");
    let output = dump(&path, &[]);
    assert!(!output.status.success());
    assert_eq!(stdout(&output), "");
    let message = stderr(&output);
    assert!(message.contains("file offset 0x0"), "{message}");
    assert!(message.contains("header.magic"), "{message}");
    assert!(message.contains("invalid.xex"), "{message}");
}

#[test]
fn a_wrong_key_fails_with_offset_and_field() {
    let mut builder = SampleLayout::default().builder();
    builder.encryption = FixtureEncryption::UnknownKey;
    let built = builder.build();
    let path = write_fixture("wrong-key.xex", &built.bytes);
    let output = dump(&path, &[]);
    assert!(!output.status.success());
    let message = stderr(&output);
    let offset = format!("file offset {:#x}", built.security_offset + 0x150);
    assert!(message.contains(&offset), "{message}");
    assert!(message.contains("security_info.aes_key"), "{message}");
    assert!(message.contains("no known key"), "{message}");
}

#[test]
fn corrupt_lzx_fails_with_offset_and_field() {
    let mut builder = SampleLayout::default().builder();
    builder.compression = FixtureCompression::LzxChunks(vec![vec![0; 64]]);
    let built = builder.build();
    let path = write_fixture("corrupt-lzx.xex", &built.bytes);
    let output = dump(&path, &[]);
    assert!(!output.status.success());
    let message = stderr(&output);
    let offset = format!("file offset {:#x}", built.blocks[0].offset + 26);
    assert!(message.contains(&offset), "{message}");
    assert!(
        message.contains("compressed_block[0].chunk[0]"),
        "{message}"
    );
    assert!(message.contains("corrupt LZX"), "{message}");
}

#[test]
fn a_missing_file_fails_naming_it() {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no-such-file.xex");
    let output = dump(&path, &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("no-such-file.xex"));
}

/// A sample that imports an ordinal missing from the table.
fn warning_bytes() -> Vec<u8> {
    let layout = SampleLayout::default();
    let mut builder = layout.builder();
    builder.image = layout.image();
    layout.with_imports(
        &mut builder,
        &[LibrarySpec {
            name: "xboxkrnl.exe",
            imports: vec![ImportSpec {
                ordinal: 0x7FF0,
                thunk: true,
            }],
        }],
    );
    builder.build().bytes
}

#[test]
fn warnings_go_to_stderr_and_do_not_stop_the_listing() {
    let path = write_fixture("warning.xex", &warning_bytes());
    let output = dump(&path, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let message = stderr(&output);
    assert!(message.contains("warning: "), "{message}");
    assert!(message.contains("0x7ff0"), "{message}");
    let text = stdout(&output);
    let line = "  0x7ff0 function slot=0x82020100 thunk=0x82010400 <unknown>";
    assert!(text.lines().any(|l| l == line), "{text}");
}

#[test]
fn strict_mode_turns_warnings_into_a_failure() {
    let path = write_fixture("strict.xex", &warning_bytes());
    let output = dump(&path, &["--strict"]);
    assert!(!output.status.success());
    assert_eq!(stdout(&output), "");
    let message = stderr(&output);
    assert!(message.contains("0x7ff0"), "{message}");
    assert!(message.contains("--strict"), "{message}");
}

#[test]
fn strict_mode_accepts_a_clean_file() {
    let path = write_fixture("strict-clean.xex", &sample_bytes());
    let output = dump(&path, &["--strict"]);
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn a_modified_image_is_flagged_in_the_listing() {
    let mut built = SampleLayout::default().builder().build();
    let edit = built.header_size as usize + 0x1_0010;
    built.bytes[edit] ^= 1;
    let path = write_fixture("modified.xex", &built.bytes);
    let output = dump(&path, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("page run 1"));
    let text = stdout(&output);
    assert!(text.lines().any(|line| line == "page digests:  MISMATCH"));
}
