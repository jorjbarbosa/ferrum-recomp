# Contributing

## Before you start

Run `cargo build --workspace && cargo test --workspace` to see the tree green before you change
anything. Before you open a pull request, run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo clippy -p ferrum-runtime -p ferrum-harness --all-targets --features trace -- -D warnings
cargo test -p ferrum-runtime -p ferrum-harness --features trace
```

## Where decisions live

There is no separate design document. A decision is explained where the code that carries it lives:
the module doc says what the module does and why, and a behavior that comes from a source names it,
such as the section of an ISA book or the file of another project. A test pins every decision that a
change could silently undo.

## Language

Everything in this repository is in **English**: code, identifiers, comments, docs, commit messages,
TOML keys and error messages.

## License and file headers

Dual-licensed **MIT OR Apache-2.0** (`LICENSE-MIT`, `LICENSE-APACHE`). New source files start with
the same two-line SPDX header as the existing ones, in the comment syntax of the file type. Markdown
files carry no header. Third-party files (the Xenia test suites under `tests/` and the ordinal tables
under `crates/ferrum-xex/tables/xenia/`) keep their own license and notice.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project is dual-licensed as above, without any additional terms or conditions.

## Code quality

- Edition 2024. The minimum Rust version is `rust-version` in the workspace `Cargo.toml`.
- `cargo fmt` (config in `rustfmt.toml`) and `cargo clippy --workspace --all-targets -- -D warnings`
  are clean before every commit.
- `#![forbid(unsafe_code)]` in every crate except `ferrum-runtime`. There, every `unsafe` block has a
  `// SAFETY:` comment with the invariant it relies on.
- `#![warn(missing_docs)]` in library crates. Every public item has a doc comment that says what it
  does, not what it is named.
- Errors: a `thiserror` enum per crate, `anyhow` only in the `ferrum` binary. No `unwrap()` or
  `expect()` in library code outside tests, except on invariants, with a comment saying why it
  cannot fail.
- Integer arithmetic on guest values is explicit: `wrapping_*`, `checked_*`, or `as` with a comment
  when truncation is the intent.
- Unit tests live next to the code (`#[cfg(test)]`), integration tests in `tests/`. New instruction
  semantics are not done until the matching Xenia test passes; what the suites do not cover gets a
  synthetic program in `crates/ferrum-harness/src/synthetic.rs`.
- A test case that has to fail goes on the exclusion list of `crates/ferrum-harness/manifest.toml`,
  with the reason and the source that decides it.
- Keep functions small. A `match` over hundreds of opcodes is fine; a 300-line function body is not.

## Commit messages

An imperative subject under 72 characters with a scope prefix: `xex:`, `decoder:`, `analysis:`,
`codegen:`, `runtime:`, `cli:`, `tests:`, `docs:`, `ci:`. The body explains why when the diff does not
show it.

## References

- PowerPC ISA 2.02, Books I to III (IBM), and for VMX chapter 6 of Book I of the Power ISA v3.1C
  (OpenPOWER Foundation), since version 2.02 has no vector facility. When sources disagree, the ISA
  books decide.
- Xenia and Xenia Canary document what the books do not: VMX128, the kernel, the test suites.
  XenonRecomp is a reference for how Xbox 360 code behaves once recompiled.
- Read other projects to understand a behavior, and take facts from them (encodings, constants,
  data layouts), citing the file. Do not translate their code into Rust. No GPL code in any form;
  running a GPL tool such as objdump as a black box is fine.
- Game content is never committed, and neither are game configs, which belong to the port of each
  game. `docs/config.example.toml` documents every key of the config.
