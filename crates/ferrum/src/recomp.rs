// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The `ferrum recomp` subcommand: from a XEX and its TOML config to the Rust workspace of the
//! game.

use std::collections::BTreeMap;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ferrum_analysis::{Code, Discovery, Function, Input, SaveRestore, discover, find_save_restore};
use ferrum_codegen::{
    Error as CodegenError, Import, Layout, Library, NonLocal, OutputFile, Program, Statistics,
    write_workspace,
};
use ferrum_xex::{Image, ImportKind, Xex};

use crate::config::Config;

/// The index of the exception data directory, which locates `.pdata`, in the PE headers.
const EXCEPTION_DIRECTORY: usize = 3;
/// Offset of the export count in the XEX export table.
const EXPORT_COUNT_OFFSET: u32 = 0x24;
/// Size of the XEX export table before its list of addresses.
const EXPORT_TABLE_HEADER: u32 = 0x2C;

/// Recompiles the game the config at `path` describes. With `strict`, warnings are errors.
pub fn run(path: &Path, strict: bool) -> Result<()> {
    let config = Config::load(path)?;
    check_out(&config.out)?;
    let file =
        fs::read(&config.xex).with_context(|| format!("cannot read {}", config.xex.display()))?;
    let xex =
        Xex::parse(&file).with_context(|| format!("cannot parse {}", config.xex.display()))?;
    let mut warnings: Vec<String> = xex.warnings.iter().map(ToString::to_string).collect();
    let image = &xex.image;
    let code = Code::new(image.base, &image.data);
    let code_ranges = code_ranges(image);
    let routines = routines(image, &code_ranges);
    let imports = imports(image, &mut warnings);
    let mut skip = config.skip.clone();
    skip.extend(export_table(&xex, &code_ranges));
    let input = Input {
        code,
        data_ranges: data_ranges(image),
        code_ranges,
        pdata: image
            .pdata
            .iter()
            .map(|entry| Function {
                addr: entry.begin,
                size: entry.size(),
            })
            .collect(),
        entries: std::iter::once(image.entry)
            .chain(image.exports.iter().map(|export| export.address))
            .collect(),
        thunks: imports.iter().filter_map(|import| import.thunk).collect(),
        routines: &routines,
        functions: config.functions.clone(),
        skip,
        table_entries: config.table_entries.clone(),
        longjmp: config.longjmp,
    };
    let discovery = discover(&input).context("function discovery failed")?;
    warnings.extend(discovery.warnings.iter().map(ToString::to_string));
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    if strict && !warnings.is_empty() {
        bail!(
            "{} warning(s) treated as errors by --strict",
            warnings.len()
        );
    }

    let program = Program::new(code, discovery.functions.iter().copied(), &routines)
        .with_rules(discovery.rules.clone())
        .with_non_local(NonLocal {
            setjmp: config.setjmp,
            longjmp: config.longjmp,
        })
        .with_imports(imports)
        .with_hooks(config.hooks.clone())
        .with_trap_as_nop(config.trap_as_nop);
    let statistics = program.statistics()?;
    let layout = Layout {
        name: config.crate_name.clone(),
        functions_per_crate: config.functions_per_crate,
        runtime: runtime(&config)?,
    };
    let files = match program.workspace(&layout) {
        Ok(files) => files,
        Err(CodegenError::MissingEmit { counts }) => {
            print_opcodes(&statistics);
            eprintln!("opcodes without emit_*:");
            for (name, count) in &counts {
                eprintln!("  {name} x{count}");
            }
            bail!("{} opcode(s) have no emit_*", counts.len());
        }
        Err(other) => return Err(other).context("cannot generate the workspace"),
    };
    let written = write_workspace(&config.out, &files)
        .with_context(|| format!("cannot write {}", config.out.display()))?;
    copy_lock(&config.out)?;
    print_summary(&discovery, &statistics, &files, written, &config.out);
    Ok(())
}

/// The repository this binary was built from.
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives in crates/ferrum")
        .to_path_buf()
}

/// The directory of `ferrum-runtime` the output names, as an absolute path, since the generated
/// manifests lie elsewhere.
fn runtime(config: &Config) -> Result<PathBuf> {
    let runtime = config
        .runtime
        .clone()
        .unwrap_or_else(|| repository().join("crates").join("ferrum-runtime"));
    let runtime = std::path::absolute(&runtime)
        .with_context(|| format!("cannot resolve {}", runtime.display()))?;
    if !runtime.join("Cargo.toml").is_file() {
        bail!("{} holds no ferrum-runtime crate", runtime.display());
    }
    Ok(runtime)
}

/// Fails if `out` lies inside a Cargo workspace that does not list it under `exclude`.
///
/// Cargo makes a path dependency under a workspace's directory a member of that workspace unless
/// `exclude` holds it (The Cargo Book, "Workspaces"). A port that depends on the generated root
/// crate from inside its own workspace would then have the `workspace = true` keys of the
/// generated manifests resolved against the port's root manifest instead of the output's, and the
/// build fails ("`workspace.package.edition` was not defined"). Excluded, the output keeps its
/// own workspace, and both the port and the output build.
fn check_out(out: &Path) -> Result<()> {
    fs::create_dir_all(out).with_context(|| format!("cannot create {}", out.display()))?;
    let out = fs::canonicalize(out)?;
    for dir in out.ancestors().skip(1) {
        let manifest = dir.join("Cargo.toml");
        let Ok(text) = fs::read_to_string(&manifest) else {
            continue;
        };
        let Some(workspace) = toml::from_str::<toml::Table>(&text)
            .ok()
            .and_then(|mut table| table.remove("workspace"))
        else {
            continue;
        };
        if !excludes(dir, &workspace, &out) {
            bail!(
                "{} lies inside the Cargo workspace of {}; list it under `exclude` in that \
                 workspace, or write the output elsewhere",
                out.display(),
                dir.display()
            );
        }
    }
    Ok(())
}

/// Whether the `exclude` list of the workspace whose root is `root` holds `out`. Its entries are
/// paths relative to the root, and each excludes everything under it.
fn excludes(root: &Path, workspace: &toml::Value, out: &Path) -> bool {
    workspace
        .get("exclude")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .filter_map(|entry| fs::canonicalize(root.join(entry)).ok())
        .any(|excluded| out.starts_with(excluded))
}

/// Copies the `Cargo.lock` of the repository into `out`, if it has none yet, so that Cargo can
/// check the output with the same versions and without the network.
fn copy_lock(out: &Path) -> Result<()> {
    let lock = out.join("Cargo.lock");
    let source = repository().join("Cargo.lock");
    if !lock.exists() && source.is_file() {
        fs::copy(&source, &lock)
            .with_context(|| format!("cannot copy Cargo.lock to {}", lock.display()))?;
    }
    Ok(())
}

/// The bytes of the image that a section holds, as a range of guest addresses.
fn held(image: &Image, address: u32, end: u64) -> Option<Range<u32>> {
    let image_end = u64::from(image.base) + image.data.len() as u64;
    let end = end.min(image_end);
    // Both bounds lie in the 32-bit address space.
    (u64::from(address) < end).then_some(address..end as u32)
}

/// The executable sections, clipped to the bytes the image holds.
fn code_ranges(image: &Image) -> Vec<Range<u32>> {
    image
        .sections
        .iter()
        .filter(|section| section.is_executable())
        .filter_map(|section| held(image, section.address, section.end()))
        .collect()
}

/// The other sections, without the one that holds `.pdata`.
fn data_ranges(image: &Image) -> Vec<Range<u32>> {
    let pdata = image
        .pe
        .data_directories
        .get(EXCEPTION_DIRECTORY)
        .filter(|directory| directory.rva != 0)
        .map(|directory| image.base.wrapping_add(directory.rva));
    image
        .sections
        .iter()
        .filter(|section| !section.is_executable())
        .filter(|section| !pdata.is_some_and(|addr| section.contains(addr)))
        .filter_map(|section| held(image, section.address, section.end()))
        .collect()
}

/// The save and restore routines of the code sections.
fn routines(image: &Image, code_ranges: &[Range<u32>]) -> SaveRestore {
    let mut routines = SaveRestore::new();
    for range in code_ranges {
        let len = (range.end - range.start) as usize;
        if let Some(bytes) = image.bytes_at(range.start, len) {
            routines.extend(find_save_restore(&Code::new(range.start, bytes)));
        }
    }
    routines
}

/// The imports of the image, for code generation, with a warning for each that it cannot wire.
fn imports(image: &Image, warnings: &mut Vec<String>) -> Vec<Import> {
    let mut imports = Vec::new();
    for library in &image.imports {
        let kind = Library::from_name(&library.name);
        if matches!(kind, Library::Other(_)) {
            warnings.push(format!(
                "{} has no kernel trait; calls to its imports panic",
                library.name
            ));
        }
        for import in &library.imports {
            let function = import.kind == ImportKind::Function;
            if !function && import.name.is_none() {
                warnings.push(format!(
                    "variable {:#x} of {} has no name; its slot keeps the value of the image",
                    import.ordinal, library.name
                ));
            }
            imports.push(Import {
                library: kind.clone(),
                ordinal: import.ordinal,
                name: import.name.map(str::to_owned),
                function,
                slot: import.slot,
                thunk: import.thunk,
            });
        }
    }
    imports
}

/// The XEX export table, as a range to skip, when it lies in code.
fn export_table(xex: &Xex, code_ranges: &[Range<u32>]) -> Option<Function> {
    let table = xex.header.security.export_table;
    if table == 0 || !code_ranges.iter().any(|range| range.contains(&table)) {
        return None;
    }
    let count = xex
        .image
        .bytes_at(table.checked_add(EXPORT_COUNT_OFFSET)?, 4)?;
    let count = u32::from_be_bytes(count.try_into().ok()?);
    Some(Function {
        addr: table,
        size: EXPORT_TABLE_HEADER.checked_add(count.checked_mul(4)?)?,
    })
}

fn print_opcodes(statistics: &Statistics) {
    let mut opcodes: Vec<(&str, usize)> = statistics
        .opcodes
        .iter()
        .map(|(&name, &count)| (name, count))
        .collect();
    opcodes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let total: usize = opcodes.iter().map(|&(_, count)| count).sum();
    println!("instructions: {total}, {} opcodes", opcodes.len());
    for (name, count) in opcodes {
        println!("  {name:<12} {count}");
    }
}

fn print_summary(
    discovery: &Discovery,
    statistics: &Statistics,
    files: &[OutputFile],
    written: usize,
    out: &Path,
) {
    let mut sources: BTreeMap<String, usize> = BTreeMap::new();
    for source in discovery.sources.values() {
        *sources.entry(format!("{source:?}")).or_default() += 1;
    }
    let sources: Vec<String> = sources
        .iter()
        .map(|(source, count)| format!("{source} {count}"))
        .collect();
    println!(
        "functions: {} ({})",
        discovery.functions.len(),
        sources.join(", ")
    );
    println!("never return: {}", discovery.rules.no_return.len());
    println!(
        "jump tables: {} resolved, {} unresolved",
        statistics.jump_tables, statistics.unresolved_tables
    );
    print_opcodes(statistics);
    let crates = files
        .iter()
        .filter(|file| file.path.ends_with("/Cargo.toml"))
        .count();
    let out = std::path::absolute(out).unwrap_or_else(|_| out.to_path_buf());
    println!(
        "wrote {written} of {} files, {crates} crates, to {}",
        files.len(),
        out.display()
    );
}
