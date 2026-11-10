// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Generates Rust for the test files of the manifest and for the synthetic programs, into
//! `OUT_DIR/suite.rs`, twice: with a dispatcher at the top of the file, and as structured code in
//! its module `structured`, which holds the same names. The tests run both.

#[path = "src/manifest.rs"]
#[allow(dead_code)]
mod manifest;
#[path = "src/map.rs"]
#[allow(dead_code)]
mod map;
#[path = "src/synthetic.rs"]
#[allow(dead_code)]
mod synthetic;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

use ferrum_analysis::{Code, Function, Input, Rules, discover, find_save_restore};
use ferrum_codegen::{
    Action, ControlFlow, Hooks, Import, Library, MidAsm, NonLocal, Override, PRELUDE, Program,
    thunk_name,
};

use manifest::{Group, Manifest};

const CODE_BASE: u32 = synthetic::BASE;

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("set by Cargo"));
    let tests = crate_dir.join("../../tests");
    for path in [
        "manifest.toml",
        "src/manifest.rs",
        "src/map.rs",
        "src/synthetic.rs",
        "../../tests/xenia-ppc",
        "../../tests/xenia-canary-ppc",
    ] {
        println!("cargo::rerun-if-changed={path}");
    }
    let text = fs::read_to_string(crate_dir.join("manifest.toml")).expect("manifest.toml");
    let manifest = Manifest::parse(&text).unwrap_or_else(|e| panic!("manifest.toml: {e}"));
    let mut out = generate_all(&manifest, &tests, ControlFlow::Dispatch);
    let structured = generate_all(&manifest, &tests, ControlFlow::Structured);
    writeln!(out, "pub mod structured {{\n{structured}}}").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("set by Cargo"));
    fs::write(out_dir.join("suite.rs"), out).expect("write suite.rs");
}

/// The modules of the test files and of the synthetic programs, generated with `control_flow`,
/// and their tables `FILES` and `SYNTHETIC`.
fn generate_all(manifest: &Manifest, tests: &Path, control_flow: ControlFlow) -> String {
    // Modules by directory, then the table of files.
    let mut modules: BTreeMap<String, String> = BTreeMap::new();
    let mut files = String::new();
    for (name, &group) in &manifest.files {
        if group == Group::NotATest {
            continue;
        }
        let (dir, stem) = name
            .split_once('/')
            .expect("a manifest name is <directory>/<stem>");
        let module_dir = dir.replace('-', "_");
        let counts: BTreeMap<u32, u32> = manifest
            .jump_tables
            .iter()
            .filter(|table| table.file == *name)
            .map(|table| (CODE_BASE + table.bctr, table.entries))
            .collect();
        let code = match generate(
            &tests.join(dir),
            stem,
            group.discovers(),
            counts,
            control_flow,
        ) {
            Ok(generated) => {
                let module = modules.entry(module_dir.clone()).or_default();
                write_module(module, stem, &generated);
                format!("crate::Generated::Code(&{module_dir}::{stem}::FUNCTIONS)")
            }
            Err(error) => format!("crate::Generated::Failed({error:?})"),
        };
        writeln!(
            files,
            "    crate::GeneratedFile {{ name: {name:?}, group: crate::manifest::Group::{group:?}, code: {code} }},"
        )
        .unwrap();
    }

    let mut out = String::new();
    for (dir, content) in &modules {
        writeln!(out, "pub mod {dir} {{\n{content}}}").unwrap();
    }
    writeln!(
        out,
        "pub static FILES: &[crate::GeneratedFile] = &[\n{files}];"
    )
    .unwrap();
    write_synthetic(&mut out, control_flow);
    out
}

/// The generated functions of one file, their entries with the Rust path the table holds for
/// each, and the size of its code in words.
struct Generated {
    text: String,
    entries: Vec<(u32, String)>,
    words: usize,
}

/// Generates the functions of one test file with `control_flow`: one per `test_` symbol of its
/// `.map`, or, with `discovers`, those that function discovery finds from the test symbols, with
/// `counts` as the entry counts of jump tables.
fn generate(
    dir: &Path,
    stem: &str,
    discovers: bool,
    counts: BTreeMap<u32, u32>,
    control_flow: ControlFlow,
) -> Result<Generated, String> {
    let bin = fs::read(dir.join(format!("{stem}.bin"))).map_err(|e| format!("{stem}.bin: {e}"))?;
    let map = fs::read_to_string(dir.join(format!("{stem}.map")))
        .map_err(|e| format!("{stem}.map: {e}"))?;
    let symbols = map::parse_map(&map)?;
    let functions: Vec<Function> = map::test_functions(&symbols, bin.len())?
        .iter()
        .map(|f| Function {
            addr: CODE_BASE + f.offset,
            size: f.size,
        })
        .collect();
    if !discovers {
        return generate_code(
            &bin,
            &functions,
            Rules::default(),
            Extras::default(),
            control_flow,
        );
    }
    let (functions, rules) = discover_functions(&bin, &functions, counts)?;
    generate_code(&bin, &functions, rules, Extras::default(), control_flow)
}

/// What a synthetic program wires besides its functions.
#[derive(Default)]
struct Extras {
    non_local: NonLocal,
    imports: Vec<Import>,
    hooks: Hooks,
}

impl Extras {
    /// The extras of a synthetic program, with its word offsets as addresses.
    fn of(program: &synthetic::Synthetic) -> Self {
        let entry = synthetic::Synthetic::entry;
        let imports = program
            .imports
            .iter()
            .map(|import| Import {
                library: Library::Xboxkrnl,
                ordinal: import.ordinal,
                name: Some(import.name.to_owned()),
                function: true,
                slot: Some(import.slot),
                thunk: Some(entry(import.thunk)),
            })
            .collect();
        let action = |action| match action {
            synthetic::SyntheticAction::Continue => Action::Continue,
            synthetic::SyntheticAction::Return => Action::Return,
            synthetic::SyntheticAction::Jump(word) => Action::Jump(entry(word)),
            synthetic::SyntheticAction::ReturnIfTrue => Action::ReturnIfTrue,
            synthetic::SyntheticAction::JumpIfTrue(word) => Action::JumpIfTrue(entry(word)),
        };
        let hooks = Hooks {
            overrides: program
                .overrides
                .iter()
                .map(|&(word, name)| Override {
                    addr: entry(word),
                    name: name.to_owned(),
                })
                .collect(),
            midasm: program
                .midasm
                .iter()
                .map(|hook| MidAsm {
                    addr: entry(hook.word),
                    name: hook.name.to_owned(),
                    after: hook.after,
                    action: action(hook.action),
                })
                .collect(),
        };
        Self {
            non_local: NonLocal {
                setjmp: program.setjmp.map(entry),
                longjmp: program.longjmp.map(entry),
            },
            imports,
            hooks,
        }
    }
}

/// The functions discovery finds in a test file, entered at its test functions. Any warning is
/// an error: the files are small enough to have none.
fn discover_functions(
    bin: &[u8],
    tests: &[Function],
    counts: BTreeMap<u32, u32>,
) -> Result<(Vec<Function>, Rules), String> {
    let code = Code::new(CODE_BASE, bin);
    let routines = find_save_restore(&code);
    let end = u32::try_from(bin.len())
        .ok()
        .and_then(|len| CODE_BASE.checked_add(len))
        .ok_or("a .bin past the end of the address space")?;
    let input = Input {
        code,
        code_ranges: std::iter::once(CODE_BASE..end).collect(),
        data_ranges: Vec::new(),
        pdata: Vec::new(),
        entries: tests.iter().map(|f| f.addr).collect(),
        thunks: Default::default(),
        routines: &routines,
        functions: Vec::new(),
        skip: Vec::new(),
        table_entries: counts,
        longjmp: None,
    };
    let found = discover(&input).map_err(|e| e.to_string())?;
    if let Some(warning) = found.warnings.first() {
        return Err(format!("discovery: {warning}"));
    }
    Ok((found.functions, found.rules))
}

fn generate_code(
    bin: &[u8],
    functions: &[Function],
    rules: Rules,
    extras: Extras,
    control_flow: ControlFlow,
) -> Result<Generated, String> {
    let code = Code::new(CODE_BASE, bin);
    let routines = find_save_restore(&code);
    let thunks: Vec<u32> = extras.imports.iter().filter_map(|i| i.thunk).collect();
    let has_imports = !extras.imports.is_empty();
    let program = Program::new(code, functions.iter().copied(), &routines)
        .with_rules(rules)
        .with_non_local(extras.non_local)
        .with_imports(extras.imports)
        .with_hooks(extras.hooks)
        .with_control_flow(control_flow);
    let mut text = program.generate().map_err(|e| e.to_string())?;
    if control_flow == ControlFlow::Structured {
        // A function that falls back to the dispatcher would test the wrong form, so in these
        // small programs a rejected or too deep form is a failure.
        let statistics = program.statistics().map_err(|e| e.to_string())?;
        if let Some((addr, why)) = statistics.rejected.first() {
            return Err(format!("structured form of {addr:#010x} rejected: {why}"));
        }
        if let Some((addr, depth)) = statistics.deep.first() {
            return Err(format!(
                "structured code of {addr:#010x} nests {depth} deep"
            ));
        }
    }
    if has_imports {
        text.push_str(&format!(
            "pub mod imports {{\n{}}}\n",
            program.imports_file()
        ));
    }
    let mut entries: Vec<(u32, String)> = functions
        .iter()
        .filter_map(|f| program.table_path(f.addr).map(|path| (f.addr, path)))
        .collect();
    entries.extend(
        thunks
            .into_iter()
            .map(|t| (t, format!("imports::{}", thunk_name(t)))),
    );
    Ok(Generated {
        text,
        entries,
        words: bin.len().div_ceil(4),
    })
}

/// A module with the functions of one file and their dense table from [`CODE_BASE`].
fn write_module(out: &mut String, name: &str, generated: &Generated) {
    writeln!(out, "pub mod {name} {{").unwrap();
    out.push_str(PRELUDE);
    out.push_str("use ferrum_runtime::GuestFn;\n\n");
    out.push_str(&generated.text);
    let mut table = vec!["None".to_owned(); generated.words];
    for (entry, path) in &generated.entries {
        let index = ((entry - CODE_BASE) / 4) as usize;
        table[index] = format!("Some({path})");
    }
    writeln!(
        out,
        "pub static FUNCTIONS: [Option<GuestFn>; {}] = [{}];",
        generated.words,
        table.join(", ")
    )
    .unwrap();
    out.push_str("}\n");
}

/// The synthetic programs, generated with `control_flow`, which have to generate: they are ours.
fn write_synthetic(out: &mut String, control_flow: ControlFlow) {
    let mut modules = String::new();
    let mut table = String::new();
    for program in synthetic::programs() {
        let functions: Vec<Function> = program
            .functions
            .iter()
            .map(|&(offset, words)| Function {
                addr: synthetic::Synthetic::entry(offset),
                size: 4 * words,
            })
            .collect();
        let extras = Extras::of(&program);
        let rules = Rules {
            no_return: extras.non_local.longjmp.into_iter().collect(),
            ..Rules::default()
        };
        let generated = generate_code(&program.bytes(), &functions, rules, extras, control_flow)
            .unwrap_or_else(|e| panic!("synthetic program {}: {e}", program.name));
        write_module(&mut modules, program.name, &generated);
        writeln!(
            table,
            "    ({:?}, &synthetic::{}::FUNCTIONS),",
            program.name, program.name
        )
        .unwrap();
    }
    writeln!(out, "pub mod synthetic {{\n{modules}}}").unwrap();
    writeln!(
        out,
        "pub static SYNTHETIC: &[(&str, &[Option<ferrum_runtime::GuestFn>])] = &[\n{table}];"
    )
    .unwrap();
}
