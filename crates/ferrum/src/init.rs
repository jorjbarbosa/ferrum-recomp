// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The `ferrum init` subcommand: the skeleton of a port, with the config that `ferrum recomp`
//! reads and a binary crate that runs the generated code.
//!
//! The config holds only the keys that `ferrum recomp` cannot run without. A key goes in when a
//! run shows that it is needed; nothing that the analysis finds by itself goes in.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::recomp::repository;

/// The directory of the output of `ferrum recomp`, relative to the port.
const GENERATED: &str = "generated";

/// The patterns of the port's `.gitignore`: the game files, the output of `ferrum recomp` and the
/// build output.
const IGNORED: [&str; 3] = ["/game/", "/generated/", "/target/"];

/// The `.gitignore` of a port that has none.
const GITIGNORE: &str = "\
# The game files, which each developer supplies from a copy of the game they own
/game/
# The output of ferrum recomp
/generated/
/target/
";

/// The root manifest of the port.
const ROOT_MANIFEST: &str = r#"[workspace]
members = ["crates/*"]
# Workspaces of their own under this directory: the output of ferrum recomp, and the ferrum
# checkout when it lies here. Without the exclude, Cargo would make the path dependencies under
# them members of this workspace, and resolve their `workspace = true` keys against this manifest.
exclude = @EXCLUDE@
resolver = "3"

[workspace.package]
version = "0.1.0"
edition = "2024"
publish = false

[workspace.dependencies]
ferrum-runtime = { path = @RUNTIME@ }
ferrum-xex = { path = @XEX@ }
@NAME@-ppc = { path = @PPC@ }

# The profile that ferrum recomp writes for the generated crates. Cargo reads profiles only from
# the root manifest of the workspace it builds, so a build from here repeats it for every package
# that is not a member: the generated crates, and the ferrum runtime with them.
[profile.dev.package."*"]
@PROFILE@
[profile.release.package."*"]
@PROFILE@"#;

/// The manifest of the port's binary crate.
const CRATE_MANIFEST: &str = r#"[package]
name = "@NAME@"
description = "Runs the recompiled code of the game"
version.workspace = true
edition.workspace = true
publish.workspace = true

[dependencies]
ferrum-runtime.workspace = true
ferrum-xex.workspace = true
@NAME@-ppc.workspace = true
"#;

/// The `main.rs` of the port's binary crate.
const MAIN: &str = r#"//! Runs the recompiled code of the game from the entry point of its XEX.
//!
//! The kernel below implements nothing: every import and imported variable that the game reaches
//! panics with its name and the caller's LR. Implement them as the game reaches them.

use std::error::Error;

use ferrum_runtime::{FnTable, HookTable, Kernels, Memory, PpcContext, Xam, Xboxkrnl, enter};
use ferrum_xex::Xex;

/// The XEX that config/@NAME@.toml recompiles, from the root of the port.
const XEX: &str = "game/default.xex";

/// The kernel of the port.
struct Kernel;

impl Xboxkrnl for Kernel {}
impl Xam for Kernel {}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| XEX.to_owned());
    let xex = Xex::parse(&std::fs::read(&path)?)?;
    let mem = Memory::new()?;
    mem.write_bytes(xex.image.base, &xex.image.data);

    let mut table = FnTable::new();
    @CRATE@::register(&mut table)?;
    // Replacements for the functions that config/@NAME@.toml lists under [hooks] function:
    // table.set(0x82003000, my_function)?;

    // The hooks that config/@NAME@.toml lists under [hooks] midasm, installed with `set`.
    let hooks = HookTable::new();
    let kernel = Kernel;
    let k = Kernels {
        krnl: &kernel,
        xam: &kernel,
        table: &table,
        hooks: &hooks,
    };
    @CRATE@::imports::load(&mem, &k);
    let missing = @CRATE@::hooks::missing(&table, &hooks);
    if !missing.is_empty() {
        return Err(format!("hooks not installed: {missing:?}").into());
    }

    // A real kernel gives the main thread a stack (r1), its processor control region (r13) and
    // its thread-local storage before the entry point runs.
    let mut ctx = PpcContext::new();
    let entry = table
        .get(xex.image.entry)
        .ok_or("the entry point was not recompiled")?;
    enter(entry, &mut ctx, &mem, &k);
    Ok(())
}
"#;

/// The config of `ferrum recomp` for the port.
const CONFIG: &str = r#"# The config of `ferrum recomp` for this port. Paths are relative to this file. It holds only the
# keys that ferrum recomp cannot run without: add one when a run shows that it is needed. Every
# key is documented in @DOCS@.

[main]
xex = "../game/default.xex"
out = "../generated"
crate_name = "@NAME@-ppc"
# The runtime that the port's crates depend on too, so that Cargo builds one copy of it.
runtime = @RUNTIME@
"#;

/// Writes the skeleton of a port into `dir`, named `name` or else after `dir`. Files that
/// already exist are an error, unless `force` overwrites them; an existing `.gitignore` only gets
/// the patterns it lacks, and an existing `Cargo.lock` stays.
pub fn run(dir: &Path, name: Option<&str>, force: bool) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    // Paths are compared canonical, but the messages and the writes use `dir` as given: on
    // Windows a canonical path carries the verbatim prefix (`\\?\C:\...`).
    let canonical = fs::canonicalize(dir)?;
    let name = match name {
        Some(name) => name.to_owned(),
        None => canonical
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("{} has no name to give the port", dir.display()))?
            .to_owned(),
    };
    check_name(&name)?;
    let ferrum = fs::canonicalize(repository())?;
    if canonical.starts_with(&ferrum) {
        bail!(
            "{} lies inside the ferrum checkout at {}; put the port elsewhere",
            dir.display(),
            repository().display()
        );
    }

    let files = files(&name, &Paths::new(&canonical, &ferrum));
    let conflicts: Vec<String> = files
        .iter()
        .filter(|(path, _)| dir.join(path).exists())
        .map(|(path, _)| path.display().to_string())
        .collect();
    if !conflicts.is_empty() && !force {
        bail!(
            "{} already holds {}; pass --force to overwrite",
            dir.display(),
            conflicts.join(", ")
        );
    }
    for (path, text) in &files {
        let path = dir.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        fs::write(&path, text).with_context(|| format!("cannot write {}", path.display()))?;
    }
    gitignore(dir)?;
    lock(dir, &ferrum)?;
    let game = dir.join("game");
    fs::create_dir_all(&game).with_context(|| format!("cannot create {}", game.display()))?;

    println!("wrote the port `{name}` in {}", dir.display());
    println!("next:");
    println!("  1. copy the game files into game/, default.xex at least");
    println!("  2. ferrum recomp config/{name}.toml");
    println!("  3. cargo run -p {name}");
    Ok(())
}

/// Fails unless `name` can name the port's package and, with `-ppc`, the generated root crate:
/// an ASCII letter, then ASCII letters, digits, `-` and `_`.
fn check_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        bail!(
            "`{name}` cannot name a port: it takes an ASCII letter, then ASCII letters, digits, \
             `-` and `_`; pass another with --name"
        );
    }
    Ok(())
}

/// How the files of a port name the ferrum checkout.
#[derive(Debug, PartialEq, Eq)]
struct Paths {
    /// The checkout from the root of the port: relative when the two share a root, absolute
    /// otherwise.
    from_root: String,
    /// The checkout from the port's `config` directory.
    from_config: String,
    /// The `exclude` list of the port's workspace.
    exclude: Vec<String>,
}

impl Paths {
    /// The paths for a port at `port` and the checkout at `ferrum`, both canonical.
    fn new(port: &Path, ferrum: &Path) -> Self {
        let (from_root, from_config) = match relative(port, ferrum) {
            Some(path) => (path.clone(), format!("../{path}")),
            None => (absolute(ferrum), absolute(ferrum)),
        };
        let mut exclude = vec![GENERATED.to_owned()];
        if ferrum.starts_with(port) {
            exclude.push(from_root.clone());
        }
        Self {
            from_root,
            from_config,
            exclude,
        }
    }
}

/// The path of `to` relative to `from`, with `/` between components, or `None` if the two share
/// no root, as on two drives of Windows.
fn relative(from: &Path, to: &Path) -> Option<String> {
    let from: Vec<Component<'_>> = from.components().collect();
    let to: Vec<Component<'_>> = to.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    if common == 0 {
        return None;
    }
    let mut parts: Vec<&str> = vec![".."; from.len() - common];
    for component in &to[common..] {
        parts.push(component.as_os_str().to_str()?);
    }
    if parts.is_empty() {
        return Some(".".to_owned());
    }
    Some(parts.join("/"))
}

/// `path` as a manifest names it: with `/` between components, and without the verbatim prefix
/// that `fs::canonicalize` gives on Windows (`\\?\C:\...`), which Cargo does not need.
fn absolute(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    if let Some(share) = text.strip_prefix("//?/UNC/") {
        return format!("//{share}");
    }
    text.strip_prefix("//?/")
        .map_or(text.clone(), str::to_owned)
}

/// `text` as a TOML string.
fn quote(text: &str) -> String {
    toml::Value::String(text.to_owned()).to_string()
}

/// The files of a port named `name`, by their path in the port.
fn files(name: &str, paths: &Paths) -> Vec<(PathBuf, String)> {
    let krate = format!("{}_ppc", name.replace('-', "_"));
    let exclude: Vec<String> = paths.exclude.iter().map(|entry| quote(entry)).collect();
    let fill = |template: &str| {
        template
            .replace("@EXCLUDE@", &format!("[{}]", exclude.join(", ")))
            .replace(
                "@RUNTIME@",
                &quote(&format!("{}/crates/ferrum-runtime", paths.from_root)),
            )
            .replace(
                "@XEX@",
                &quote(&format!("{}/crates/ferrum-xex", paths.from_root)),
            )
            .replace("@PPC@", &quote(&format!("{GENERATED}/{name}-ppc")))
            .replace("@PROFILE@", ferrum_codegen::PROFILE)
            .replace("@CRATE@", &krate)
            .replace("@NAME@", name)
    };
    let config = CONFIG
        .replace(
            "@DOCS@",
            &format!("{}/docs/config.example.toml", paths.from_config),
        )
        .replace(
            "@RUNTIME@",
            &quote(&format!("{}/crates/ferrum-runtime", paths.from_config)),
        )
        .replace("@NAME@", name);
    let krate_dir = Path::new("crates").join(name);
    vec![
        (PathBuf::from("Cargo.toml"), fill(ROOT_MANIFEST)),
        (krate_dir.join("Cargo.toml"), fill(CRATE_MANIFEST)),
        (krate_dir.join("src").join("main.rs"), fill(MAIN)),
        (Path::new("config").join(format!("{name}.toml")), config),
    ]
}

/// Writes the port's `.gitignore`, or adds to an existing one the patterns it lacks.
fn gitignore(dir: &Path) -> Result<()> {
    let path = dir.join(".gitignore");
    let Ok(text) = fs::read_to_string(&path) else {
        return fs::write(&path, GITIGNORE)
            .with_context(|| format!("cannot write {}", path.display()));
    };
    let missing: Vec<&str> = IGNORED
        .into_iter()
        .filter(|pattern| !text.lines().any(|line| line.trim() == *pattern))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut text = text;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for pattern in missing {
        text.push_str(pattern);
        text.push('\n');
    }
    fs::write(&path, text).with_context(|| format!("cannot write {}", path.display()))
}

/// Copies the `Cargo.lock` of the ferrum checkout into the port, if it has none, so that the
/// port builds with the dependency versions ferrum was tested with, and without the network.
fn lock(dir: &Path, ferrum: &Path) -> Result<()> {
    let target = dir.join("Cargo.lock");
    if target.exists() {
        return Ok(());
    }
    let source = ferrum.join("Cargo.lock");
    fs::copy(&source, &target)
        .with_context(|| format!("cannot copy {} to {}", source.display(), target.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_takes_a_letter_then_letters_digits_hyphens_and_underscores() {
        for name in ["roan", "roan-rs", "game_2", "A1"] {
            assert!(check_name(name).is_ok(), "{name}");
        }
        for name in ["", "1game", "-game", "my game", "jogo-ção", "a.b"] {
            assert!(check_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn the_checkout_is_named_relative_to_the_port_when_they_share_a_root() {
        let port = Path::new("/work/roan-rs");
        assert_eq!(
            relative(port, Path::new("/work/rust-recomp")).as_deref(),
            Some("../rust-recomp")
        );
        assert_eq!(
            relative(port, Path::new("/work/roan-rs/tools/ferrum-recomp")).as_deref(),
            Some("tools/ferrum-recomp")
        );
        assert_eq!(
            relative(Path::new("/a/b/c"), Path::new("/x")).as_deref(),
            Some("../../../x")
        );
        assert_eq!(relative(port, port).as_deref(), Some("."));
    }

    #[cfg(windows)]
    #[test]
    fn two_drives_have_no_relative_path() {
        assert_eq!(
            relative(Path::new(r"C:\port"), Path::new(r"D:\ferrum")),
            None
        );
        assert_eq!(absolute(Path::new(r"\\?\D:\a\ferrum")), "D:/a/ferrum");
        assert_eq!(
            absolute(Path::new(r"\\?\UNC\server\share\ferrum")),
            "//server/share/ferrum"
        );
    }

    #[test]
    fn a_checkout_inside_the_port_is_excluded_from_its_workspace() {
        let port = Path::new("/work/roan-rs");
        let inside = Paths::new(port, Path::new("/work/roan-rs/tools/ferrum-recomp"));
        assert_eq!(
            inside,
            Paths {
                from_root: "tools/ferrum-recomp".to_owned(),
                from_config: "../tools/ferrum-recomp".to_owned(),
                exclude: vec!["generated".to_owned(), "tools/ferrum-recomp".to_owned()],
            }
        );
        let beside = Paths::new(port, Path::new("/work/rust-recomp"));
        assert_eq!(beside.from_root, "../rust-recomp");
        assert_eq!(beside.from_config, "../../rust-recomp");
        assert_eq!(beside.exclude, vec!["generated".to_owned()]);
    }

    #[test]
    fn the_files_name_the_port_and_the_checkout() {
        let paths = Paths::new(
            Path::new("/work/roan-rs"),
            Path::new("/work/roan-rs/tools/ferrum-recomp"),
        );
        let files = files("roan", &paths);
        let text = |path: &str| {
            files
                .iter()
                .find(|(file, _)| file == Path::new(path))
                .map(|(_, text)| text.as_str())
                .unwrap_or_else(|| panic!("no {path}"))
        };
        let root = text("Cargo.toml");
        assert!(
            root.contains(r#"exclude = ["generated", "tools/ferrum-recomp"]"#),
            "{root}"
        );
        assert!(
            root.contains(
                r#"ferrum-runtime = { path = "tools/ferrum-recomp/crates/ferrum-runtime" }"#
            ),
            "{root}"
        );
        assert!(
            root.contains(r#"roan-ppc = { path = "generated/roan-ppc" }"#),
            "{root}"
        );
        assert!(root.contains(ferrum_codegen::PROFILE), "{root}");
        assert!(!root.contains('@'), "{root}");
        let config = text("config/roan.toml");
        assert!(config.contains(r#"crate_name = "roan-ppc""#), "{config}");
        assert!(
            config.contains(r#"runtime = "../tools/ferrum-recomp/crates/ferrum-runtime""#),
            "{config}"
        );
        assert!(
            config.contains("../tools/ferrum-recomp/docs/config.example.toml"),
            "{config}"
        );
        let main = text("crates/roan/src/main.rs");
        assert!(main.contains("roan_ppc::register(&mut table)?;"), "{main}");
        assert!(main.contains("config/roan.toml"), "{main}");
        for (path, text) in &files {
            assert!(!text.contains('@'), "{}: {text}", path.display());
        }
    }
}
