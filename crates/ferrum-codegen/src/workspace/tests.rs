// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The layout of the output workspace, checked on its text. Whether it compiles is checked by
//! `ferrum-scale`, which runs `cargo check` over a generated workspace.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ferrum_analysis::{Code, Function, SaveRestore};
use ferrum_decoder::{CrBit, Fpr, Gpr, Insn};

use super::*;
use crate::{NonLocal, function_name};

const BASE: u32 = 0x8200_0000;

fn li(rt: u8, si: i16) -> Insn {
    Insn::Addi {
        rt: Gpr(rt),
        ra: Gpr(0),
        si,
    }
}

fn blr() -> Insn {
    Insn::Bclr {
        bo: 20,
        bi: CrBit(0),
        bh: 0,
        lk: false,
    }
}

/// A branch from word `from` to word `to`.
fn b(from: u32, to: u32, lk: bool) -> Insn {
    let li = (to as i32 - from as i32) * 4;
    Insn::B { li, aa: false, lk }
}

/// `count` functions of two words, `li r3, i; blr`, as instructions and (word, size) pairs.
fn leaves(count: u32) -> (Vec<Insn>, Vec<(u32, u32)>) {
    let insns = (0..count).flat_map(|i| [li(3, i as i16), blr()]).collect();
    let functions = (0..count).map(|i| (2 * i, 2)).collect();
    (insns, functions)
}

fn layout(functions_per_crate: usize) -> Layout {
    Layout {
        name: "game-ppc".to_owned(),
        functions_per_crate,
        runtime: PathBuf::from(r"C:\ferrum\runtime"),
    }
}

/// The workspace of the functions at the given word offsets and sizes in words.
fn workspace(
    insns: &[Insn],
    functions: &[(u32, u32)],
    layout: &Layout,
) -> Result<Vec<OutputFile>, Error> {
    let bytes: Vec<u8> = insns
        .iter()
        .flat_map(|insn| insn.encode().to_be_bytes())
        .collect();
    let functions = functions.iter().map(|&(offset, words)| Function {
        addr: BASE + 4 * offset,
        size: 4 * words,
    });
    let routines = SaveRestore::new();
    Program::new(Code::new(BASE, &bytes), functions, &routines).workspace(layout)
}

fn leaves_workspace(count: u32, functions_per_crate: usize) -> Vec<OutputFile> {
    let (insns, functions) = leaves(count);
    workspace(&insns, &functions, &layout(functions_per_crate)).unwrap()
}

fn file<'a>(files: &'a [OutputFile], path: &str) -> &'a str {
    &files
        .iter()
        .find(|file| file.path == path)
        .unwrap_or_else(|| panic!("no file {path}"))
        .text
}

fn toml(text: &str) -> toml::Table {
    text.parse()
        .unwrap_or_else(|e| panic!("invalid TOML: {e}\n{text}"))
}

/// The entries listed in the `FUNCTIONS` of a crate's `lib.rs`, checking that each names its own
/// function.
fn listed(lib: &str) -> Vec<u32> {
    lib.lines()
        .filter_map(|line| line.strip_prefix("    (0x"))
        .map(|rest| {
            let (hex, name) = rest.split_once(", ").unwrap();
            let addr = u32::from_str_radix(hex, 16).unwrap();
            assert_eq!(name, format!("{}),", function_name(addr)));
            addr
        })
        .collect()
}

#[test]
fn functions_are_split_in_address_order_into_crates_of_the_given_size() {
    let files = leaves_workspace(7, 3);
    let paths: Vec<&str> = files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "Cargo.toml",
            "game-ppc/Cargo.toml",
            "game-ppc/src/lib.rs",
            "game-ppc/src/table.rs",
            "game-ppc/src/imports.rs",
            "game-ppc/src/hooks.rs",
            "game-ppc-000/Cargo.toml",
            "game-ppc-000/src/lib.rs",
            "game-ppc-001/Cargo.toml",
            "game-ppc-001/src/lib.rs",
            "game-ppc-002/Cargo.toml",
            "game-ppc-002/src/lib.rs",
        ]
    );
    for i in 0..7 {
        let definition = format!("pub fn {}(", function_name(BASE + 8 * i));
        let defined_in: Vec<&str> = files
            .iter()
            .filter(|file| file.text.contains(&definition))
            .map(|file| file.path.as_str())
            .collect();
        let expected = format!("game-ppc-{:03}/src/lib.rs", i / 3);
        assert_eq!(defined_in, [expected], "function {i}");
        let count: usize = files
            .iter()
            .map(|file| file.text.matches(&definition).count())
            .sum();
        assert_eq!(count, 1, "function {i} is defined once");
    }
}

#[test]
fn each_crate_lists_its_functions_and_the_root_registers_every_list() {
    let files = leaves_workspace(7, 3);
    let mut seen = BTreeMap::new();
    for (index, size) in [(0, 3), (1, 3), (2, 1)] {
        let lib = file(&files, &format!("game-ppc-{index:03}/src/lib.rs"));
        let entries = listed(lib);
        let expected: Vec<u32> = (0..size).map(|i| BASE + 8 * (3 * index + i)).collect();
        assert_eq!(entries, expected, "crate {index}");
        assert!(lib.contains(&format!(
            "pub static FUNCTIONS: [(u32, GuestFn); {size}] = ["
        )));
        for entry in entries {
            *seen.entry(entry).or_insert(0) += 1;
        }
    }
    let all: Vec<u32> = (0..7).map(|i| BASE + 8 * i).collect();
    assert_eq!(seen.keys().copied().collect::<Vec<_>>(), all);
    assert!(seen.values().all(|&n| n == 1), "one entry per function");

    let table = file(&files, "game-ppc/src/table.rs");
    // From the first entry to the last: seven leaves of two words.
    assert!(table.contains("pub const BASE: u32 = 0x82000000;"));
    assert!(table.contains("pub const WORDS: usize = 13;"));
    let lists: Vec<&str> = table
        .lines()
        .filter(|line| line.ends_with("::FUNCTIONS,"))
        .map(str::trim)
        .collect();
    assert_eq!(
        lists,
        [
            "&game_ppc_000::FUNCTIONS,",
            "&game_ppc_001::FUNCTIONS,",
            "&game_ppc_002::FUNCTIONS,"
        ]
    );
    assert!(table.contains("    &crate::imports::THUNKS,\n"));
    assert!(table.contains("static LISTS: [&[(u32, GuestFn)]; 4] = ["));
    assert!(table.contains("table.register_entries(BASE, WORDS, &LISTS)"));
    let lib = file(&files, "game-ppc/src/lib.rs");
    assert!(lib.contains("pub use table::{register, BASE, WORDS};"));
}

#[test]
fn calls_to_another_crate_go_through_the_table() {
    // Crate 000: sub_82000000 calls sub_8200000c (same crate), then calls and tail-calls
    // sub_82000014 (crate 001).
    let insns = [
        b(0, 3, true),
        b(1, 5, true),
        b(2, 5, false),
        li(3, 1),
        blr(),
        li(3, 2),
        blr(),
    ];
    let functions = [(0, 3), (3, 2), (5, 2)];
    let files = workspace(&insns, &functions, &layout(2)).unwrap();
    let lib = file(&files, "game-ppc-000/src/lib.rs");
    let lines: Vec<&str> = lib.lines().map(str::trim).collect();
    let direct = "sub_8200000c(ctx, mem, k);";
    let table = "(k.table.lookup(0x82000014, ctx.lr))(ctx, mem, k); // sub_82000014";
    assert_eq!(lines.iter().filter(|&&l| l == direct).count(), 1, "{lib}");
    assert_eq!(lines.iter().filter(|&&l| l == table).count(), 2, "{lib}");
    assert!(!lib.contains("sub_82000014(ctx"), "{lib}");
    assert!(
        !lib.contains("game_ppc_001"),
        "no crate names another: {lib}"
    );

    // One module calls everything directly, as the harness needs.
    let bytes: Vec<u8> = insns
        .iter()
        .flat_map(|insn| insn.encode().to_be_bytes())
        .collect();
    let routines = SaveRestore::new();
    let program = Program::new(
        Code::new(BASE, &bytes),
        functions.iter().map(|&(offset, words)| Function {
            addr: BASE + 4 * offset,
            size: 4 * words,
        }),
        &routines,
    );
    let text = program.generate().unwrap();
    assert!(!text.contains("k.table"), "{text}");
    assert_eq!(text.matches("sub_82000014(ctx, mem, k);").count(), 2);
}

#[test]
fn every_crate_forbids_unsafe_code_and_quiets_the_lints_of_machine_written_code() {
    let files = leaves_workspace(5, 2);
    let manifest = toml(file(&files, "Cargo.toml"));
    let members = manifest["workspace"]["members"].as_array().unwrap();
    assert_eq!(members.len(), 4);
    for member in members {
        let lib = file(&files, &format!("{}/src/lib.rs", member.as_str().unwrap()));
        let lines: Vec<&str> = lib.lines().collect();
        assert!(lines.contains(&"#![forbid(unsafe_code)]"), "{member}");
        assert!(
            lines.contains(&"#![allow(unused, clippy::all, missing_docs)]"),
            "{member}"
        );
    }
}

#[test]
fn the_manifests_name_every_crate_and_the_generated_profile() {
    let files = leaves_workspace(5, 2);
    let root = toml(file(&files, "Cargo.toml"));
    let members: Vec<&str> = root["workspace"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap())
        .collect();
    assert_eq!(
        members,
        ["game-ppc", "game-ppc-000", "game-ppc-001", "game-ppc-002"]
    );
    let runtime = &root["workspace"]["dependencies"]["ferrum-runtime"]["path"];
    assert_eq!(runtime.as_str(), Some(r"C:\ferrum\runtime"));
    for profile in ["dev", "release"] {
        let profile = root["profile"][profile].as_table().unwrap();
        assert_eq!(profile["debug"].as_bool(), Some(false));
        assert_eq!(profile["incremental"].as_bool(), Some(false));
        assert_eq!(profile["overflow-checks"].as_bool(), Some(false));
        assert_eq!(profile["codegen-units"].as_integer(), Some(256));
    }

    for (index, member) in members.iter().enumerate() {
        let manifest = toml(file(&files, &format!("{member}/Cargo.toml")));
        assert_eq!(manifest["package"]["name"].as_str(), Some(*member));
        let dependencies = manifest["dependencies"].as_table().unwrap();
        let mut names: Vec<&str> = dependencies.keys().map(String::as_str).collect();
        names.sort_unstable();
        if index == 0 {
            // The root crate depends on the runtime and on every other crate.
            let mut expected = vec!["ferrum-runtime"];
            expected.extend(&members[1..]);
            assert_eq!(names, expected);
            for part in &members[1..] {
                let path = dependencies[*part]["path"].as_str().unwrap();
                assert_eq!(path, format!("../{part}"));
            }
        } else {
            assert_eq!(
                names,
                ["ferrum-runtime"],
                "{member} depends on no other crate"
            );
        }
    }
}

#[test]
fn crate_numbers_widen_past_999_crates() {
    let files = leaves_workspace(1001, 1);
    let root = toml(file(&files, "Cargo.toml"));
    let members = root["workspace"]["members"].as_array().unwrap();
    assert_eq!(members.len(), 1002);
    assert_eq!(members[1].as_str(), Some("game-ppc-0000"));
    assert_eq!(members[1001].as_str(), Some("game-ppc-1000"));
    assert_eq!(files.len(), 6 + 2 * 1001);
    // A single crate keeps three digits.
    let files = leaves_workspace(1, 2000);
    assert_eq!(files[6].path, "game-ppc-000/Cargo.toml");
}

#[test]
fn layouts_that_cannot_be_written_are_errors() {
    let (insns, functions) = leaves(3);
    let error = workspace(&insns, &functions, &layout(0)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid output layout: functions_per_crate is zero"
    );
    for name in ["", "9-ppc", "game ppc", "game/ppc", "jogo-ç"] {
        let layout = Layout {
            name: name.to_owned(),
            ..layout(2)
        };
        let error = workspace(&insns, &functions, &layout).unwrap_err();
        assert!(
            matches!(&error, Error::InvalidLayout { why } if why.contains("not a valid crate name")),
            "{name:?}: {error}"
        );
    }
    let error = workspace(&insns, &[], &layout(2)).unwrap_err();
    assert!(matches!(error, Error::InvalidLayout { .. }), "{error}");
}

#[test]
fn missing_emits_are_counted_over_every_crate() {
    // frin decodes, but the Xenon does not have it, so it has no emit_*.
    let frin = Insn::Frin {
        frt: Fpr(1),
        frb: Fpr(2),
        rc: false,
    };
    let insns = [frin, blr(), li(3, 0), blr(), frin, frin, blr()];
    let functions = [(0, 2), (2, 2), (4, 3)];
    let error = workspace(&insns, &functions, &layout(1)).unwrap_err();
    assert_eq!(error.to_string(), "opcodes without emit_*: frin x3");
}

#[test]
fn write_workspace_writes_only_the_files_that_changed() {
    let dir = std::env::temp_dir().join(format!("ferrum-codegen-write-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let mut files = leaves_workspace(3, 2);
    assert_eq!(write_workspace(&dir, &files).unwrap(), files.len());
    assert_eq!(write_workspace(&dir, &files).unwrap(), 0);
    let index = files
        .iter()
        .position(|file| file.path == "game-ppc-000/src/lib.rs")
        .unwrap();
    files[index].text.push_str("// changed\n");
    assert_eq!(write_workspace(&dir, &files).unwrap(), 1);
    let on_disk = fs::read_to_string(dir.join("game-ppc-000").join("src").join("lib.rs")).unwrap();
    assert_eq!(on_disk, files[index].text);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_table_holds_the_runtime_longjmp_for_the_guest_one() {
    // Two leaves; the second is longjmp, which has no generated function.
    let insns = [blr(), blr()];
    let bytes: Vec<u8> = insns
        .iter()
        .flat_map(|insn| insn.encode().to_be_bytes())
        .collect();
    let functions = [BASE, BASE + 4].map(|addr| Function { addr, size: 4 });
    let routines = SaveRestore::new();
    let files = Program::new(Code::new(BASE, &bytes), functions, &routines)
        .with_non_local(NonLocal {
            setjmp: None,
            longjmp: Some(BASE + 4),
        })
        .workspace(&layout(10))
        .unwrap();
    let lib = files
        .iter()
        .find(|f| f.path == "game-ppc-000/src/lib.rs")
        .unwrap();
    assert!(
        lib.text.contains(
            "    (0x82000000, sub_82000000),
"
        ),
        "{}",
        lib.text
    );
    assert!(
        lib.text.contains(
            "    (0x82000004, ferrum_runtime::longjmp),
"
        ),
        "{}",
        lib.text
    );
    assert!(!lib.text.contains("pub fn sub_82000004"), "{}", lib.text);
}
