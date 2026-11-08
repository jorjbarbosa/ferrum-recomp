#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Jorge Barbosa

"""Regenerate the .bin, .map and .dis files of the Xenia PPC test suites under tests/.

Nothing needs this script to build or test the repository: the generated files are committed, and
CI uses them without binutils. It exists so that they can be reproduced.

There are two suites, chosen with --suite:

- `xenia` (the default): tests/xenia-ppc/, every .s file of Xenia at XENIA_COMMIT.
- `canary`: tests/xenia-canary-ppc/, the .s files of Xenia Canary at CANARY_COMMIT that are named in
  that directory's manifest.txt.

The flags and the link step are those of `GenTestsCommand` in Xenia's `xenia-build`, at
XENIA_COMMIT, for both suites. There is one difference: gentests only takes files named `instr_*`
and `seq_*`, and this script takes every .s of a suite, so that the disassembler oracle has no file
left out.

    python scripts/regen-xenia-ppc.py --binutils DIR [--suite S]            # rewrite the files
    python scripts/regen-xenia-ppc.py --binutils DIR [--suite S] --check    # compare only
    python scripts/regen-xenia-ppc.py --binutils DIR [--suite S] --import-from GIT_DIR

`--import-from` first copies the .s files and the license out of a clone of the suite's
repository, taking the bytes of the git objects at the suite's commit so that the line endings of
the checkout do not matter. A partial clone (`--filter=blob:none`) is enough.

The tools must be binutils 2.24 with the vmx128 patch, as in
https://github.com/benvanik/binutils-ppc-cygwin. The Cygwin build rejects Windows paths with a
warning, so the tools run inside a temporary directory and only ever see relative names.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

XENIA_COMMIT = "95a5c3ee250f80c3b9d139658649d9ffb6db3eec"
CANARY_COMMIT = "80cecb77b9666cb528e7cb81a462ad0b8ad7b109"
TESTING_DIR = "src/xenia/cpu/ppc/testing"
EXPECTED_VERSION = "GNU assembler (GNU Binutils) 2.24"
TOOL_PREFIX = "powerpc-none-elf-"


@dataclass(frozen=True)
class Suite:
    """One directory of test sources and where its files come from."""

    directory: Path
    commit: str
    expected_sources: int
    # A file listing the .s names to take, one per line, or None to take every .s at the commit.
    manifest: str | None


SUITES = {
    "xenia": Suite(ROOT / "tests" / "xenia-ppc", XENIA_COMMIT, 167, None),
    "canary": Suite(ROOT / "tests" / "xenia-canary-ppc", CANARY_COMMIT, 96, "manifest.txt"),
}

AS_FLAGS = ["-a32", "-be", "-mregnames", "-mpower7", "-maltivec", "-mvsx", "-mvmx128", "-R"]
OBJDUMP_FLAGS = ["--adjust-vma=0x100000", "-Mpower7", "-Mvmx128", "-D", "-EB"]
# gentests passes "-A powerpc:common32" as one argument, with the space in it. Kept as it is.
LD_FLAGS = [
    "-A powerpc:common32",
    "-melf32ppc",
    "-EB",
    "-nostdlib",
    "--oformat=binary",
    "-Ttext=0x80000000",
    "-e0x80000000",
]
NM_FLAGS = ["--numeric-sort"]
# The first lines of objdump's output name the object file, which differs between machines.
DIS_HEADER_LINES = 4


def find_tool(binutils, name):
    """Return the path of one tool, with or without an .exe suffix."""
    found = shutil.which(TOOL_PREFIX + name, path=str(binutils))
    if found is None:
        sys.exit(f"error: {TOOL_PREFIX}{name} not found in {binutils}")
    return found


def run(arguments, cwd):
    """Run a tool and return its standard output as bytes, failing on any error."""
    result = subprocess.run(arguments, cwd=cwd, capture_output=True, check=False)
    if result.returncode != 0:
        message = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"{' '.join(arguments)}: exit code {result.returncode}\n{message}")
    return result.stdout


def generate(source, tools):
    """Assemble one .s file and return the bytes of its .bin, .map and .dis files."""
    with tempfile.TemporaryDirectory(prefix="ferrum-xenia-ppc-") as work:
        name = source.stem
        shutil.copyfile(source, Path(work) / source.name)
        run([tools["as"], *AS_FLAGS, f"-o{name}.o", source.name], work)
        listing = run([tools["objdump"], *OBJDUMP_FLAGS, f"{name}.o"], work)
        run([tools["ld"], *LD_FLAGS, f"-o{name}.bin", f"{name}.o"], work)
        symbols = run([tools["nm"], *NM_FLAGS, f"{name}.o"], work)
        image = (Path(work) / f"{name}.bin").read_bytes()

    if b"\r" in listing or b"\r" in symbols:
        raise RuntimeError(f"{source.name}: the tools wrote carriage returns")
    lines = listing.split(b"\n")
    if b"file format" not in lines[1]:
        raise RuntimeError(f"{source.name}: unexpected objdump header: {lines[:4]}")
    return {
        ".bin": image,
        ".map": symbols,
        ".dis": b"\n".join(lines[DIS_HEADER_LINES:]),
    }


def manifest_names(suite, out):
    """Return the .s names the suite's manifest lists, or None if the suite takes every file."""
    if suite.manifest is None:
        return None
    names = (out / suite.manifest).read_text(encoding="utf-8").split()
    if len(names) != suite.expected_sources or len(set(names)) != len(names):
        sys.exit(f"error: {suite.manifest} must list {suite.expected_sources} distinct names")
    return names


def import_sources(suite, clone, out):
    """Copy the suite's .s files and the license out of a clone, at the suite's commit."""

    def git(*arguments):
        return subprocess.run(
            ["git", "-C", str(clone), *arguments], capture_output=True, check=True
        ).stdout

    listing = git("ls-tree", "--name-only", suite.commit, f"{TESTING_DIR}/").decode()
    available = {Path(line).name for line in listing.splitlines() if line.endswith(".s")}
    names = manifest_names(suite, out)
    if names is None:
        names = sorted(available)
    missing = sorted(set(names) - available)
    if missing:
        sys.exit(f"error: not in {TESTING_DIR} at {suite.commit}: {', '.join(missing)}")
    if len(names) != suite.expected_sources:
        sys.exit(f"error: found {len(names)} .s files at {suite.commit}, not {suite.expected_sources}")
    out.mkdir(parents=True, exist_ok=True)
    for name in names:
        (out / name).write_bytes(git("cat-file", "-p", f"{suite.commit}:{TESTING_DIR}/{name}"))
    (out / "LICENSE").write_bytes(git("cat-file", "-p", f"{suite.commit}:LICENSE"))
    print(f"imported {len(names)} .s files and LICENSE from {suite.commit}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--binutils", type=Path, required=True, help="directory with the tools")
    parser.add_argument("--suite", choices=sorted(SUITES), default="xenia", help="which suite")
    parser.add_argument("--out", type=Path, help="suite directory, if not the default one")
    parser.add_argument("--import-from", type=Path, help="clone to copy the .s files from")
    parser.add_argument("--check", action="store_true", help="compare only, write nothing")
    arguments = parser.parse_args()

    suite = SUITES[arguments.suite]
    out = arguments.out or suite.directory
    if arguments.import_from and arguments.check:
        parser.error("--import-from writes files, so it cannot go with --check")
    if arguments.import_from:
        import_sources(suite, arguments.import_from, out)

    tools = {name: find_tool(arguments.binutils, name) for name in ("as", "ld", "nm", "objdump")}
    version = run([tools["as"], "--version"], None).decode().splitlines()[0]
    if version != EXPECTED_VERSION:
        sys.exit(f"error: expected {EXPECTED_VERSION!r}, found {version!r}")

    sources = sorted(out.glob("*.s"))
    names = manifest_names(suite, out)
    if len(sources) != suite.expected_sources:
        sys.exit(f"error: found {len(sources)} .s files in {out}")
    if names is not None and sorted(names) != [source.name for source in sources]:
        sys.exit(f"error: the .s files in {out} are not the ones {suite.manifest} lists")

    with ThreadPoolExecutor() as pool:
        results = list(pool.map(lambda source: generate(source, tools), sources))

    changed = 0
    for source, outputs in zip(sources, results):
        for suffix, data in outputs.items():
            target = source.with_suffix(suffix)
            if arguments.check:
                if not target.is_file() or target.read_bytes() != data:
                    print(f"differs: {target.name}", file=sys.stderr)
                    changed += 1
            else:
                target.write_bytes(data)

    if arguments.check:
        print(f"{changed} of {len(sources) * 3} generated files differ")
        return 1 if changed else 0
    print(f"wrote {len(sources) * 3} files for {len(sources)} sources, with {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
