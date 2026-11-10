// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Runs the Xenia suites and the synthetic programs through the generated code.
//!
//! The tests that run generated code are in `suite/cases.rs`, which runs twice: in the module
//! `dispatch`, on the code generated with a dispatcher, and in the module `structured_code`, on the
//! structured code of the same files and programs. The tests here check the manifest and the files
//! generated.
//!
//! Every test that runs guest code shares one `Memory`, because each one commits 4 GiB on Windows.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use ferrum_harness::annotations::{Annotation, Case, Register, parse_cases};
use ferrum_harness::generated::{FILES, structured};
use ferrum_harness::manifest::{Group, Manifest};
use ferrum_harness::map::{TestFunction, parse_map, test_functions};
use ferrum_harness::runner::{CODE_BASE, Harness, SENTINEL_LR, STACK_BASE};
use ferrum_harness::synthetic::{Synthetic, fp_op_entry, programs, vector_op_entry};
use ferrum_harness::{Generated, GeneratedFile, tests_dir};
use ferrum_runtime::{FnTable, Memory, PpcContext, V128, Vscr};

fn manifest() -> Manifest {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.toml");
    Manifest::parse(&fs::read_to_string(path).unwrap()).unwrap()
}

/// The one harness of this test binary.
fn harness() -> MutexGuard<'static, Harness> {
    static HARNESS: OnceLock<Mutex<Harness>> = OnceLock::new();
    HARNESS
        .get_or_init(|| Mutex::new(Harness::new().expect("map the guest memory")))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Reads a file of a suite, by its manifest name and a suffix.
fn suite_file(name: &str, suffix: &str) -> Vec<u8> {
    let path = tests_dir().join(format!("{name}.{suffix}"));
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The cases of a test file and the test functions of its `.map`, which have to name the same
/// symbols.
fn cases_of(name: &str) -> (Vec<Case>, Vec<TestFunction>) {
    let source = String::from_utf8(suite_file(name, "s")).unwrap();
    let cases = parse_cases(&source).unwrap_or_else(|e| panic!("{name}.s: {e}"));
    let map = String::from_utf8(suite_file(name, "map")).unwrap();
    let functions =
        test_functions(&parse_map(&map).unwrap(), suite_file(name, "bin").len()).unwrap();
    let labels: Vec<&str> = cases.iter().map(|case| case.symbol.as_str()).collect();
    let symbols: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        labels, symbols,
        "{name}: the labels of the .s and the test symbols of the .map"
    );
    (cases, functions)
}

#[test]
fn every_test_file_has_exactly_one_group() {
    let mut on_disk = BTreeSet::new();
    for dir in ["xenia-ppc", "xenia-canary-ppc"] {
        for entry in fs::read_dir(tests_dir().join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|extension| extension == "s") {
                let stem = path.file_stem().unwrap().to_string_lossy();
                on_disk.insert(format!("{dir}/{stem}"));
            }
        }
    }
    let listed: BTreeSet<String> = manifest().files.into_keys().collect();
    let without_group: Vec<&String> = on_disk.difference(&listed).collect();
    let without_file: Vec<&String> = listed.difference(&on_disk).collect();
    assert!(
        without_group.is_empty(),
        "files with no group: {without_group:?}"
    );
    assert!(
        without_file.is_empty(),
        "manifest entries with no file: {without_file:?}"
    );
}

#[test]
fn every_file_is_in_the_group_of_what_it_tests() {
    let manifest = manifest();
    let mut counts: BTreeMap<Group, usize> = BTreeMap::new();
    for group in manifest.files.values() {
        *counts.entry(*group).or_default() += 1;
    }
    let expected = [
        (Group::Integer, 155),
        (Group::Float, 10),
        (Group::Vector, 96),
        (Group::Discovery, 1),
        (Group::NotATest, 1),
    ];
    assert_eq!(counts, BTreeMap::from(expected));
    assert_eq!(
        manifest.files["xenia-ppc/seq_jumptable_constants"],
        Group::Discovery
    );
    assert_eq!(
        manifest.files["xenia-ppc/ppc_testing_native_thunks"],
        Group::NotATest
    );
    assert_eq!(manifest.files["xenia-ppc/seq_branch_carry"], Group::Integer);
}

#[test]
fn exclusions_name_cases_of_test_files() {
    let manifest = manifest();
    let mut seen = BTreeSet::new();
    for exclusion in &manifest.exclusions {
        assert!(
            seen.insert(&exclusion.case),
            "{} is listed twice",
            exclusion.case
        );
        assert!(
            !exclusion.reason.trim().is_empty(),
            "{} has no reason",
            exclusion.case
        );
        let (file, symbol) = exclusion.case.split_once(':').expect("<file>:<symbol>");
        assert!(
            manifest
                .files
                .get(file)
                .is_some_and(|group| group.is_test()),
            "{}",
            exclusion.case
        );
        let (cases, _) = cases_of(file);
        assert!(
            cases.iter().any(|case| case.symbol == symbol),
            "{} is no case",
            exclusion.case
        );
    }
}

#[test]
fn jump_table_counts_name_a_bctr_of_a_file_that_discovers() {
    let manifest = manifest();
    assert!(!manifest.jump_tables.is_empty());
    for table in &manifest.jump_tables {
        assert!(
            manifest
                .files
                .get(&table.file)
                .is_some_and(|group| group.discovers()),
            "{}",
            table.file
        );
        assert!(
            !table.reason.trim().is_empty(),
            "{} has no reason",
            table.file
        );
        let bin = suite_file(&table.file, "bin");
        let at = table.bctr as usize;
        assert_eq!(
            bin.get(at..at + 4),
            Some(&0x4E80_0420u32.to_be_bytes()[..]),
            "{} has no bctr at {:#x}",
            table.file,
            table.bctr
        );
    }
}

#[test]
fn every_test_file_is_generated_and_no_other() {
    let manifest = manifest();
    for files in [FILES, structured::FILES] {
        let generated: BTreeMap<&str, &GeneratedFile> = files.iter().map(|f| (f.name, f)).collect();
        for (name, group) in &manifest.files {
            match (
                group.is_test(),
                generated.get(name.as_str()).map(|f| f.code),
            ) {
                (false, None) | (true, Some(Generated::Code(_))) => {}
                (_, code) => panic!("{name} in {group:?} generated as {code:?}"),
            }
        }
    }
}

/// The synthetic programs written for structured code take the shapes they are there for: a
/// dispatch node for the cycle with two entries, and two loops for the nested ones.
#[test]
fn the_programs_for_structured_code_take_their_shapes() {
    let source = include_str!(concat!(env!("OUT_DIR"), "/suite.rs"));
    let structured = &source[source.find("pub mod structured {").unwrap()..];
    let module = |name: &str| {
        let start = structured.find(&format!("pub mod {name} {{")).unwrap();
        let module = &structured[start..];
        &module[..module.find("pub static FUNCTIONS").unwrap()]
    };
    assert!(module("two_entries").contains("match state_"));
    assert_eq!(module("nested_loops").matches(": loop {").count(), 2);
}

/// The tests of `suite/cases.rs` on the code generated with a dispatcher.
mod dispatch {
    use super::*;
    use ferrum_harness::generated::{FILES, SYNTHETIC};

    include!("suite/cases.rs");
}

/// The tests of `suite/cases.rs` on the structured code.
mod structured_code {
    use super::*;
    use ferrum_harness::generated::structured::{FILES, SYNTHETIC};

    include!("suite/cases.rs");
}
