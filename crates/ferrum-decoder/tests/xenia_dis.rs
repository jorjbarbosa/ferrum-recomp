// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Compares the decoder with the `.dis` files of the Xenia suite under `tests/xenia-ppc/` and of the
//! Xenia Canary tests under `tests/xenia-canary-ppc/`.
//!
//! `format_at(decode(w), address)` has to equal each line byte for byte after these rules, and no
//! others:
//!
//! 1. Only lines with a word or `...` count; section headings, labels and blank lines are not
//!    instructions. The bytes are `w` and the address goes to `format_at`.
//! 2. A branch target written `100010 <test_x+0x10>` is compared as `0x100010`, as objdump prints
//!    it without symbols. The decoder has no symbols, and neither do XEX files.
//! 3. A `...` line stands for the zero words up to the next address, each compared as `.long 0x0`.
//! 4. Where objdump printed `.long W` for its own non-zero word `W`, its text is not the
//!    reference: the decoder has to print one of the instructions of [`ORACLE_GAP`], equal to the
//!    line of the `.s` file at that position apart from spaces. That line is what `as` assembled
//!    into `W`. The source has to have exactly one code line per word, or the line fails.

use std::fs;
use std::path::{Path, PathBuf};

use ferrum_decoder::{OPCODES, decode, format, format_at, format_undecoded};

/// The suite directories under `tests/`, and how many source files each one has.
const SUITES: [(&str, usize); 2] = [("xenia-ppc", 167), ("xenia-canary-ppc", 96)];

fn suite_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests")
        .join(name)
}

/// The files of every suite with this suffix, sorted by name within each suite.
fn suite_files(suffix: &str) -> Vec<PathBuf> {
    SUITES
        .iter()
        .flat_map(|(name, _)| files_in(&suite_dir(name), suffix))
        .collect()
}

/// The files of one directory with this suffix, sorted by name.
fn files_in(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .expect("the suite directory exists")
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == suffix)
        })
        .collect();
    files.sort();
    files
}

fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

/// One word of a listing and what objdump printed for it.
#[derive(Debug)]
struct Listed {
    address: u32,
    word: u32,
    text: String,
}

/// Reads the words of a listing, leaving out what is not an instruction (rule 1).
fn parse_listing(listing: &str) -> Vec<Listed> {
    let mut words = Vec::new();
    let mut next_address = 0;
    let mut zeros_pending = false;
    for line in listing.lines() {
        let address = if line == "\t..." {
            zeros_pending = true;
            continue;
        } else if let Some((address, _)) = line.split_once(":\t") {
            address.trim()
        } else if let Some((address, _)) = line.split_once(" <").filter(|_| line.ends_with(">:")) {
            address
        } else {
            assert!(
                line.is_empty() || line.starts_with("Disassembly of section "),
                "unexpected line in a listing: {line:?}"
            );
            continue;
        };
        let address = u32::from_str_radix(address, 16).expect("hexadecimal address");
        if zeros_pending {
            // Rule 3: `...` stands for the zero words up to the next address.
            words.extend((next_address..address).step_by(4).map(|address| Listed {
                address,
                word: 0,
                text: ".long 0x0".to_owned(),
            }));
            zeros_pending = false;
        }
        next_address = address;
        if let Some((_, rest)) = line.split_once(":\t") {
            let (bytes, text) = rest.split_once('\t').expect("a tab after the bytes");
            let hex: String = bytes.split_whitespace().collect();
            let word = u32::from_str_radix(&hex, 16).expect("four hexadecimal bytes");
            words.push(Listed {
                address,
                word,
                text: text.to_owned(),
            });
            next_address = address + 4;
        }
    }
    assert!(!zeros_pending, "a listing ends in `...`");
    words
}

/// Rule 2: a branch target loses its symbol, and prints as objdump prints it without symbols.
fn without_symbol(text: &str) -> String {
    let Some((head, _)) = text.rsplit_once(" <").filter(|_| text.ends_with('>')) else {
        return text.to_owned();
    };
    let split = head.rfind([',', ' ']).expect("a branch has a mnemonic") + 1;
    format!("{}0x{}", &head[..split], &head[split..])
}

/// What the decoder prints for a word at an address.
fn actual(word: u32, address: u32) -> String {
    decode(word).map_or_else(|| format_undecoded(word), |insn| format_at(&insn, address))
}

/// The instructions objdump 2.24 prints as `.long` under every `-M` option, although the `as` of
/// the same build assembles them: the classic VMX rows after `vxor` in opcode order. Rule 4 takes
/// the `.s` line as the reference for them.
const ORACLE_GAP: [&str; 28] = [
    "mfvscr",
    "mtvscr",
    "vavgsb",
    "vavgsh",
    "vavgsw",
    "vcmpbfp.",
    "vcmpeqfp.",
    "vcmpgefp.",
    "vcmpgtfp.",
    "vcmpgtsb.",
    "vcmpgtsh.",
    "vcmpgtsw.",
    "vcmpgtub.",
    "vcmpgtuh.",
    "vcmpgtuw.",
    "vnor",
    "vsubcuw",
    "vsubsbs",
    "vsubshs",
    "vsubsws",
    "vsububs",
    "vsubuhs",
    "vsubuws",
    "vsum2sws",
    "vsum4sbs",
    "vsum4shs",
    "vsum4ubs",
    "vsumsws",
];

/// Reads the code lines of a source file, leaving out comments and labels.
///
/// Macros and data directives can make one line more or fewer than one word, so a caller has to
/// check that the count matches the listing before pairing them up.
fn source_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|code| !code.is_empty() && !code.ends_with(':'))
        .collect()
}

/// Whether objdump gave up on a word: it printed `.long` for the word of that same line. A zero word
/// is not giving up, since zero is no instruction.
fn objdump_gave_up(listed: &Listed) -> bool {
    listed.word != 0 && listed.text == format_undecoded(listed.word)
}

/// Whether what the decoder printed is one of the instructions objdump cannot print.
fn in_oracle_gap(text: &str) -> bool {
    let mnemonic = text.split_whitespace().next().unwrap_or_default();
    ORACLE_GAP.contains(&mnemonic)
}

/// Compares two instructions, ignoring only the spaces that assembly allows between operands.
fn same_instruction(a: &str, b: &str) -> bool {
    let parts = |text: &'_ str| {
        let mut words = text.split_whitespace();
        (words.next().map(str::to_owned), words.collect::<String>())
    };
    parts(a) == parts(b)
}

/// A line of a listing the decoder did not match, or that rule 4 settled.
#[derive(Debug, PartialEq, Eq)]
struct Line {
    file: String,
    address: u32,
    expected: String,
    actual: String,
}

/// The result of comparing every listing with the decoder.
#[derive(Default)]
struct Comparison {
    mismatches: Vec<Line>,
    settled_by_source: Vec<Line>,
}

/// Compares one listing with the decoder, and adds what is not a plain match to `comparison`.
fn compare_listing(path: &Path, comparison: &mut Comparison) {
    let words = parse_listing(&fs::read_to_string(path).unwrap());
    let source = fs::read_to_string(path.with_extension("s")).unwrap();
    let source = source_lines(&source);
    for (index, listed) in words.iter().enumerate() {
        let actual = actual(listed.word, listed.address);
        let mut line = Line {
            file: file_name(path),
            address: listed.address,
            expected: listed.text.clone(),
            actual,
        };
        if !objdump_gave_up(listed) {
            if line.actual != without_symbol(&listed.text) {
                comparison.mismatches.push(line);
            }
            continue;
        }
        // Rule 4. This comes before any comparison with objdump's text, because a decoder that gave
        // up on the word too would print the same `.long` and look right. Without one code line per
        // word there is no telling which line made this word, so that is a mismatch and not a guess.
        if in_oracle_gap(&line.actual)
            && source.len() == words.len()
            && same_instruction(source[index], &line.actual)
        {
            line.expected = source[index].to_owned();
            comparison.settled_by_source.push(line);
        } else {
            comparison.mismatches.push(line);
        }
    }
}

fn compare_suite() -> Comparison {
    let mut comparison = Comparison::default();
    for path in suite_files("dis") {
        compare_listing(&path, &mut comparison);
    }
    comparison
}

/// Every line of every `.dis` file matches the decoder under the rules above.
#[test]
fn every_dis_file_matches() {
    let mismatches = compare_suite().mismatches;
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

/// Keeps rule 4 narrow: any other line that comes to depend on it has to be looked at.
#[test]
fn rule_4_settles_exactly_the_lines_objdump_cannot_print() {
    let expected = [
        ("instr_vcmpxxfp.dis", 0x100000, "vcmpeqfp. v3, v4, v5"),
        ("instr_vcmpxxfp.dis", 0x10000c, "vcmpeqfp. v3, v4, v5"),
        ("instr_vcmpxxfp.dis", 0x100018, "vcmpeqfp. v3, v4, v5"),
        ("instr_vcmpxxfp.dis", 0x100024, "vcmpbfp. v3, v4, v5"),
        ("instr_vcmpxxfp.dis", 0x100030, "vcmpbfp. v3, v4, v5"),
        ("instr_vcmpxxfp.dis", 0x10003c, "vcmpbfp. v3, v4, v5"),
        ("instr_vsubshs.dis", 0x100000, "vsubshs v3, v3, v4"),
        ("instr_vsubshs.dis", 0x100008, "vsubshs v3, v3, v4"),
    ];
    let settled = compare_suite().settled_by_source;
    let summary: Vec<(&str, u32, &str)> = settled
        .iter()
        .map(|line| (line.file.as_str(), line.address, line.expected.as_str()))
        .collect();
    assert_eq!(summary, expected);
}

#[test]
fn rule_4_only_applies_where_objdump_gave_up_on_the_oracle_gap() {
    let listed = |word: u32, text: &str| Listed {
        address: 0x10_0000,
        word,
        text: text.to_owned(),
    };
    assert!(objdump_gave_up(&listed(0x1063_2740, ".long 0x10632740")));
    // objdump printed an instruction, a `.long` of some other word, or a zero word.
    assert!(!objdump_gave_up(&listed(0x1063_2740, "vor     v3,v3,v4")));
    assert!(!objdump_gave_up(&listed(0x1063_2740, ".long 0x10632741")));
    assert!(!objdump_gave_up(&listed(0, ".long 0x0")));

    assert!(in_oracle_gap("vsubshs v3,v3,v4"));
    assert!(in_oracle_gap("vcmpeqfp. v3,v4,v5"));
    // An instruction objdump can print has no excuse to come out as `.long`, and neither does the
    // form without a record bit of one that cannot.
    assert!(!in_oracle_gap("add     r3,r3,r4"));
    assert!(!in_oracle_gap("vcmpeqfp v3,v4,v5"));
    // A decoder that gives up as well is not settled by the source.
    assert!(!in_oracle_gap(".long 0x10632740"));
}

#[test]
fn same_instruction_only_ignores_spaces() {
    assert!(same_instruction("vsubshs v3, v3, v4", "vsubshs v3,v3,v4"));
    assert!(same_instruction("vor v3, v4, v5", "vor     v3,v4,v5"));
    assert!(!same_instruction("vsubshs v3, v3, v4", "vsubshs v3,v3,v5"));
    assert!(!same_instruction("vsubshs v3, v3, v4", "vsubsws v3,v3,v4"));
    assert!(!same_instruction("vsubshs v3, v3, v4", "vsubshs v3,v4,v3"));
}

#[test]
fn source_lines_leave_out_comments_and_labels() {
    let source =
        "test_x:\n  # a comment\n  #_ REGISTER_IN v3 [1, 2]\n\n  add r3, r4, r5 # why\n  blr\n";
    assert_eq!(source_lines(source), ["add r3, r4, r5", "blr"]);
}

#[test]
fn the_oracle_gap_names_instructions_of_the_table() {
    for name in ORACLE_GAP {
        let row = name.trim_end_matches('.');
        assert!(OPCODES.iter().any(|info| info.mnemonic == row), "{name}");
    }
}

/// `format`, which has no address, prints a branch target as an offset from the instruction.
#[test]
fn format_without_an_address_prints_offsets() {
    let mut branches = 0;
    for path in suite_files("dis") {
        for listed in parse_listing(&fs::read_to_string(&path).unwrap()) {
            let Some(insn) = decode(listed.word) else {
                continue;
            };
            let expected = actual(listed.word, listed.address);
            let Some(split) = expected.find("0x") else {
                assert_eq!(format(&insn), expected);
                continue;
            };
            let target = u32::from_str_radix(&expected[split + 2..], 16).unwrap();
            let offset = i64::from(target) - i64::from(listed.address);
            let sign = if offset < 0 { '-' } else { '+' };
            let relative = format!("{}.{sign}{:#x}", &expected[..split], offset.abs());
            assert_eq!(format(&insn), relative, "{}", file_name(&path));
            branches += 1;
        }
    }
    assert!(branches > 0);
}

/// Each source file comes with its generated files, and no listing is empty by accident.
#[test]
fn the_suite_is_complete() {
    for (name, count) in SUITES {
        let dir = suite_dir(name);
        assert_eq!(files_in(&dir, "s").len(), count, "{name}");
        assert!(dir.join("LICENSE").is_file(), "{name}");
    }
    let sources = suite_files("s");
    for source in &sources {
        for suffix in ["bin", "map", "dis"] {
            assert!(
                source.with_extension(suffix).is_file(),
                "{source:?} has no .{suffix}"
            );
        }
    }
    let empty: Vec<String> = suite_files("dis")
        .iter()
        .filter(|path| fs::metadata(path).unwrap().len() == 0)
        .map(|path| file_name(path))
        .collect();
    // All the instructions of these three source files are commented out.
    assert_eq!(
        empty,
        [
            "instr_vavgsh.dis",
            "instr_vpkpx.dis",
            "instr_vpkuhum128.dis"
        ]
    );
}

/// The Canary directory holds exactly the files its manifest names.
#[test]
fn the_canary_manifest_lists_its_sources() {
    let dir = suite_dir("xenia-canary-ppc");
    let manifest = fs::read_to_string(dir.join("manifest.txt")).unwrap();
    let listed: Vec<&str> = manifest.lines().collect();
    let present: Vec<String> = files_in(&dir, "s")
        .iter()
        .map(|path| file_name(path))
        .collect();
    assert_eq!(listed, present);
}

/// Every symbol of a `.map` file labels the same offset in the listing.
#[test]
fn map_symbols_are_labels_of_the_listing() {
    for path in suite_files("map") {
        let listing = fs::read_to_string(path.with_extension("dis")).unwrap();
        for line in fs::read_to_string(&path).unwrap().lines() {
            let mut parts = line.split_whitespace();
            let (offset, _, name) = (parts.next().unwrap(), parts.next(), parts.next().unwrap());
            let offset = u32::from_str_radix(offset, 16).unwrap();
            let label = format!("{:08x} <{name}>:", offset + 0x10_0000);
            assert!(listing.contains(&label), "{}: no {label}", file_name(&path));
        }
    }
}
