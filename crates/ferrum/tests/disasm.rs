// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Runs `ferrum disasm` as a process over a synthetic XEX file written to a temporary directory.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use ferrum_xex::fixtures::XexBuilder;
use ferrum_xex::fixtures::sample::{PDATA_RVA, SampleLayout};

/// The size of `.text` in the sample.
const TEXT_SIZE: u32 = 0x800;

/// The start of the first `.pdata` function of the sample, which is 4 words long.
fn text() -> u32 {
    SampleLayout::default().text()
}

/// Offset in the image of `.text`.
fn text_offset() -> usize {
    let layout = SampleLayout::default();
    (layout.text() - layout.base) as usize
}

/// A sample whose code starts with these words.
fn sample_with_code(words: &[u32]) -> XexBuilder {
    let mut builder = SampleLayout::default().builder();
    for (index, word) in words.iter().enumerate() {
        let offset = text_offset() + index * 4;
        builder.image[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    builder
}

fn write_fixture(name: &str, bytes: &[u8]) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("disasm-fixtures");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn disasm(path: &PathBuf, extra: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferrum"))
        .arg("disasm")
        .arg(path)
        .args(extra)
        .output()
        .unwrap()
}

fn addr(address: u32) -> Vec<String> {
    vec!["--addr".to_owned(), format!("{address:#x}")]
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

/// The code the listing tests run over: four words in the first function of `.pdata`, then a gap.
const CODE: [u32; 6] = [
    0x7C68_02A6, // mflr r3
    0x4800_0008, // b .+8
    0xF000_0000, // Not a Xenon instruction.
    0x4E80_0020, // blr
    0x0000_0000, // Past the end of the function.
    0x0000_0000,
];

#[test]
fn lists_a_function_in_objdump_layout_and_stops_at_its_end() {
    let path = write_fixture("function.xex", &sample_with_code(&CODE).build().bytes);
    let output = disasm(&path, &addr(text()));
    assert!(output.status.success(), "{}", stderr(&output));
    let text = text();
    let expected = format!(
        "{:8x}:\t7c 68 02 a6 \tmflr    r3\n\
         {:8x}:\t48 00 00 08 \tb       {:#x}\n\
         {:8x}:\tf0 00 00 00 \t.long 0xf0000000\n\
         {:8x}:\t4e 80 00 20 \tblr\n",
        text,
        text + 4,
        text + 12,
        text + 8,
        text + 12,
    );
    assert_eq!(stdout(&output), expected);
}

#[test]
fn starting_inside_a_function_runs_to_its_end() {
    let path = write_fixture("inside.xex", &sample_with_code(&CODE).build().bytes);
    let output = disasm(&path, &addr(text() + 8));
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).lines().count(), 2);
}

#[test]
fn outside_any_function_it_stops_at_the_next_one() {
    // Shortening the first function to 2 words leaves a gap of 2 words before the second.
    let mut builder = sample_with_code(&CODE);
    let entry = PDATA_RVA as usize + 4;
    builder.image[entry..entry + 4].copy_from_slice(&(2u32 << 8).to_be_bytes());
    let path = write_fixture("gap.xex", &builder.build().bytes);
    let output = disasm(&path, &addr(text() + 8));
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).lines().count(), 2);
}

#[test]
fn after_the_last_function_it_stops_at_the_end_of_the_section() {
    let path = write_fixture("tail.xex", &sample_with_code(&CODE).build().bytes);
    let output = disasm(&path, &addr(text() + 0x40));
    assert!(output.status.success(), "{}", stderr(&output));
    let expected = (TEXT_SIZE - 0x40) / 4;
    assert_eq!(stdout(&output).lines().count() as u32, expected);
}

#[test]
fn count_sets_the_length_and_can_cross_functions() {
    let path = write_fixture("count.xex", &sample_with_code(&CODE).build().bytes);
    let mut arguments = addr(text());
    arguments.extend(["--count".to_owned(), "6".to_owned()]);
    let output = disasm(&path, &arguments);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert_eq!(text.lines().count(), 6);
    assert!(text.ends_with("00 00 00 00 \t.long 0x0\n"), "{text}");
}

#[test]
fn count_past_the_end_of_the_section_stops_there() {
    let path = write_fixture("past.xex", &sample_with_code(&CODE).build().bytes);
    let mut arguments = addr(text());
    arguments.extend(["--count".to_owned(), "4000000000".to_owned()]);
    let output = disasm(&path, &arguments);
    assert!(output.status.success(), "{}", stderr(&output));
    let expected = TEXT_SIZE / 4;
    assert_eq!(stdout(&output).lines().count() as u32, expected);
}

#[test]
fn a_bad_address_is_an_error() {
    let path = write_fixture("bad.xex", &sample_with_code(&CODE).build().bytes);
    let unaligned = disasm(&path, &addr(text() + 2));
    assert!(!unaligned.status.success());
    assert!(
        stderr(&unaligned).contains("not aligned"),
        "{}",
        stderr(&unaligned)
    );
    let outside = disasm(&path, &addr(0x1000));
    assert!(!outside.status.success());
    assert!(
        stderr(&outside).contains("not in any section"),
        "{}",
        stderr(&outside)
    );
}

#[test]
fn a_file_that_does_not_parse_is_an_error() {
    let path = write_fixture("garbage.xex", b"not a xex file");
    let output = disasm(&path, &addr(text()));
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("cannot parse"),
        "{}",
        stderr(&output)
    );
}
