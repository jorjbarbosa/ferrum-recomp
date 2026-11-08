// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! Times Cargo over a generated workspace: the dependencies compiled once first, then cold, warm
//! and no-op runs.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};

use crate::output::{Options, Summary};

/// How to measure.
#[derive(Debug, Clone, clap::Args)]
pub struct Protocol {
    /// Runs of each scenario; the median is the result.
    #[arg(long, default_value_t = 3)]
    pub runs: usize,
    /// Also time one cold `cargo build`.
    #[arg(long)]
    pub build: bool,
    /// Run Cargo with `CARGO_INCREMENTAL=1`, which overrides `incremental = false` of the profile.
    #[arg(long)]
    pub incremental: bool,
}

/// A Cargo command over the workspace in `out`, with its own target directory.
pub fn cargo(out: &Path, target: &Path, incremental: bool) -> Command {
    let program = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(program);
    command
        .current_dir(out)
        .env("CARGO_TARGET_DIR", target)
        .env_remove("CARGO_INCREMENTAL");
    if incremental {
        command.env("CARGO_INCREMENTAL", "1");
    }
    command
}

/// One timed run of Cargo.
#[derive(Debug, Clone, Copy)]
struct Run {
    time: Duration,
    /// The most memory in use on the host during the run, where the host tells.
    peak: Option<u64>,
}

/// Runs the protocol over the workspace that `options` wrote.
pub fn run(options: &Options, summary: &Summary, protocol: &Protocol) -> Result<()> {
    let out = &options.out;
    let target = out.join("target");
    if target.exists() {
        fs::remove_dir_all(&target)
            .with_context(|| format!("cannot remove {}", target.display()))?;
    }
    let sources = sources(out)?;
    let changed = changed_crate(out, &options.name)?;
    let check = || {
        let mut command = cargo(out, &target, protocol.incremental);
        command.args(["check", "--offline"]);
        timed(command)
    };
    let runs = protocol.runs.max(1);

    let first = check()?;
    report("check, dependencies included", &[first]);
    let mut cold = Vec::new();
    for _ in 0..runs {
        touch(&sources)?;
        cold.push(check()?);
    }
    report("check, cold", &cold);
    let mut warm = Vec::new();
    for run in 0..runs {
        change_one_function(&changed, run)?;
        warm.push(check()?);
    }
    report("check, warm", &warm);
    let noop: Vec<Run> = (0..runs).map(|_| check()).collect::<Result<_>>()?;
    report("check, no-op", &noop);

    let mut build = None;
    if protocol.build {
        let mut command = cargo(out, &target, protocol.incremental);
        command.args(["build", "--offline", "-p", "ferrum-runtime"]);
        timed(command)?;
        touch(&sources)?;
        let mut command = cargo(out, &target, protocol.incremental);
        command.args(["build", "--offline"]);
        let run = timed(command)?;
        report("build, cold", &[run]);
        build = Some(run);
    }

    // A Markdown table row: functions per crate, crates, then medians in seconds.
    let seconds = |runs: &[Run]| format!("{:.1}", median(runs).as_secs_f64());
    println!(
        "| {} | {} | {} | {} | {} | {} | {} |",
        options.per_crate,
        summary.crates - 1,
        seconds(&[first]),
        seconds(&cold),
        seconds(&warm),
        seconds(&noop),
        build.map_or("-".to_owned(), |run| seconds(&[run])),
    );
    Ok(())
}

/// Runs `command`, which has to succeed, and times it. On Linux it also samples the memory in use.
fn timed(mut command: Command) -> Result<Run> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let start = Instant::now();
    let child = command.spawn().context("cannot run cargo")?;
    let done = AtomicBool::new(false);
    let (output, time, peak) = thread::scope(|scope| {
        let sampler = scope.spawn(|| {
            let mut peak = None;
            while !done.load(Ordering::Relaxed) {
                if let Some(used) = memory_in_use() {
                    peak = Some(peak.map_or(used, |p: u64| p.max(used)));
                }
                thread::sleep(Duration::from_millis(100));
            }
            peak
        });
        let output = child.wait_with_output();
        let time = start.elapsed();
        done.store(true, Ordering::Relaxed);
        (
            output,
            time,
            sampler.join().expect("the sampler does not panic"),
        )
    });
    let output = output.context("cannot wait for cargo")?;
    if !output.status.success() {
        bail!(
            "cargo failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(Run { time, peak })
}

/// Prints the runs of one scenario and their median.
fn report(name: &str, runs: &[Run]) {
    let times: Vec<String> = runs
        .iter()
        .map(|run| format!("{:.1} s", run.time.as_secs_f64()))
        .collect();
    let peak = runs.iter().filter_map(|run| run.peak).max();
    let peak = peak.map_or(String::new(), |bytes| {
        format!(", peak {:.1} GiB in use", bytes as f64 / f64::from(1 << 30))
    });
    println!(
        "{name}: {} (median {:.1} s{peak})",
        times.join(", "),
        median(runs).as_secs_f64()
    );
}

fn median(runs: &[Run]) -> Duration {
    let mut times: Vec<Duration> = runs.iter().map(|run| run.time).collect();
    times.sort_unstable();
    times[times.len() / 2]
}

/// Every generated `.rs` file: `<crate>/src/*.rs`.
fn sources(out: &Path) -> Result<Vec<PathBuf>> {
    let mut sources = Vec::new();
    for entry in fs::read_dir(out)? {
        let src = entry?.path().join("src");
        if src.is_dir() {
            for file in fs::read_dir(&src)? {
                let path = file?.path();
                if path.extension().is_some_and(|e| e == "rs") {
                    sources.push(path);
                }
            }
        }
    }
    sources.sort();
    Ok(sources)
}

/// The `lib.rs` of the middle `<name>-NNN` crate, whose function the warm runs change.
fn changed_crate(out: &Path, name: &str) -> Result<PathBuf> {
    let prefix = format!("{name}-");
    let mut parts: Vec<PathBuf> = fs::read_dir(out)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .collect();
    parts.sort();
    match parts.get(parts.len() / 2) {
        Some(part) => Ok(part.join("src").join("lib.rs")),
        None => bail!("no {prefix}NNN crate in {}", out.display()),
    }
}

/// Marks every file as modified now, so that Cargo checks every generated crate again.
fn touch(files: &[PathBuf]) -> Result<()> {
    let now = SystemTime::now();
    for path in files {
        fs::File::options()
            .write(true)
            .open(path)
            .and_then(|file| file.set_modified(now))
            .with_context(|| format!("cannot touch {}", path.display()))?;
    }
    Ok(())
}

/// Adds a statement to the function in the middle of `lib`, as a regenerated function would
/// change it: the spans of every function after it move too.
fn change_one_function(lib: &Path, run: usize) -> Result<()> {
    let text = fs::read_to_string(lib)?;
    let marker = "    let mut pc: u32 = ";
    let starts: Vec<usize> = text.match_indices(marker).map(|(at, _)| at).collect();
    let Some(&start) = starts.get(starts.len() / 2) else {
        bail!("no function in {}", lib.display());
    };
    let end = start + text[start..].find('\n').context("a line ends")? + 1;
    let statement = format!("    ctx.r[0] = ctx.r[0].wrapping_add({});\n", run + 1);
    let changed = format!("{}{statement}{}", &text[..end], &text[end..]);
    fs::write(lib, changed)?;
    Ok(())
}

/// The memory in use on the host, from `/proc/meminfo`.
#[cfg(target_os = "linux")]
fn memory_in_use() -> Option<u64> {
    let info = fs::read_to_string("/proc/meminfo").ok()?;
    let field = |name: &str| -> Option<u64> {
        let line = info.lines().find(|line| line.starts_with(name))?;
        let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kib * 1024)
    };
    Some(field("MemTotal:")?.saturating_sub(field("MemAvailable:")?))
}

/// Other hosts do not report it.
#[cfg(not(target_os = "linux"))]
fn memory_in_use() -> Option<u64> {
    None
}
