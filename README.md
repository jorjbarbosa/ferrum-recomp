# ferrum-recomp

ferrum-recomp is a static recompiler for Xbox 360 games. It reads a retail executable (XEX2,
PowerPC) and writes a Cargo workspace in which every guest function is a Rust function. The
generated code is safe Rust: every generated crate forbids `unsafe`, and the one crate they depend
on, `ferrum-runtime`, keeps its `unsafe` to the memory mapping, each block with the invariant it
relies on.

The recompiler does not run a game by itself. The kernel, graphics, audio and input belong to a
port: a separate project that links the generated workspace, implements the kernel calls the game
makes, and starts its main thread.

## Status

**Pre-alpha.** Whole retail games recompile into Rust that compiles. None has run yet, because
that takes a port, and none exists so far.

These games went through the whole pipeline: `ferrum recomp` with no opcode left without an
emitter, then `cargo check` of the output with no error.

| Game | Functions | Instructions | Jump tables | Crates | `cargo check`, cold |
|---|---:|---:|---|---:|---:|
| Naruto: Rise of a Ninja | 24,094 | 1,573,119 | 348 resolved, 1 not | 242 | 2 min 27 s |
| Naruto: The Broken Bond | 32,440 | 2,946,910 | 464 resolved, 7 not | 326 | 5 min 29 s |
| Need for Speed: Most Wanted (USA) | 56,276 | 2,032,502 | 500 resolved, 28 not | 564 | 1 min 33 s |

Each config names only the executable, the output and the crate name: the analysis finds `setjmp`
and `longjmp` in all three. Most jump tables left unresolved have no bound check anywhere in the
code, such as a `switch` on an argument the compiler trusts, and a few hold other functions'
entries. Each becomes a lookup in the function table at run time, unless the config gives its entry
count. The times are from one Windows desktop and only
show the order of magnitude.

## How it works

1. **Load.** `ferrum-xex` reads the XEX2 headers, decrypts the payload (AES-128-CBC), decompresses
   it (basic or LZX) and lays out the PE image with its sections, `.pdata`, exports and imports.
   Import ordinals become names through Xenia's tables of `xboxkrnl.exe` and `xam.xex`.
2. **Decode.** `ferrum-decoder` decodes every Xenon instruction, VMX128 included, and prints it in
   objdump's syntax.
3. **Analyze.** `ferrum-analysis` finds the functions: `.pdata`, the entry point and the exports,
   branch targets (second entries into a function included), pointers in data, a sweep of the gaps
   and the overrides of the config. It finds the functions that never return, splits each function
   into basic blocks, recognizes the register save and restore routines and the C runtime's
   `setjmp` and `longjmp` by what they do, and resolves jump tables: the instructions before each
   `bctr` give the table, and the intervals of the registers over the function's blocks bound its
   index, wherever the code checks it.
4. **Generate.** `ferrum-codegen` writes each function as a `loop` over a `match` on the guest
   program counter, one arm per basic block. An instruction becomes a few statements over the guest
   context, the memory and the helpers of `ferrum-runtime`. Calls to import thunks become calls to
   the kernel traits, `setjmp` and `longjmp` work across frames by unwinding, and the functions are
   split into crates of 100, in address order, so that Cargo checks them in parallel.

The output for a game looks like this:

```text
game-ppc/
  Cargo.toml       workspace and generated profile
  game-ppc/        root crate: register, imports::load, hooks::missing
  game-ppc-000/    guest functions, 100 per crate
  game-ppc-001/
  ...
```

The root crate registers every function in a `FnTable`, which indirect calls and calls between
crates go through.

## Getting started

You need Rust 1.99.1 or newer, and a game you own.

```sh
cargo build --release -p ferrum
```

Look at an executable:

```sh
ferrum dump game/default.xex                       # headers, sections, .pdata, imports
ferrum disasm game/default.xex --addr 0x82001000   # the function at an address
```

Start a port with `ferrum init`, outside the ferrum checkout, then recompile the game into it:

```sh
ferrum init ../my-port --name game          # the name of the directory by default
cp path/to/default.xex ../my-port/game/
ferrum recomp ../my-port/config/game.toml   # --strict turns warnings into errors
cd ../my-port
cargo run -p game
```

`ferrum init` writes the port's workspace, the config of `ferrum recomp` and a binary crate that
runs the generated code (see [Writing a port](#writing-a-port)):

```text
my-port/
  Cargo.toml          workspace; excludes generated/, and the ferrum checkout if it lies here
  Cargo.lock          a copy of this repository's, for the same dependency versions
  config/game.toml    the config of ferrum recomp
  crates/game/        the port's binary crate
  game/               the game files, ignored by git
  generated/          the output of ferrum recomp, ignored by git
```

It names the ferrum checkout it was built from, by a relative path when it can. A port that keeps
ferrum as a git submodule builds `ferrum` from that submodule, and its workspace excludes it. The
directory may already hold other files; `init` refuses to overwrite its own files without
`--force`, and only adds to an existing `.gitignore`.

The config it writes holds only the keys that `ferrum recomp` cannot run without:

```toml
[main]
xex = "../game/default.xex"
out = "../generated"
crate_name = "game-ppc"
runtime = "../../ferrum-recomp/crates/ferrum-runtime"
```

[`docs/config.example.toml`](docs/config.example.toml) documents every key: functions the
analysis misses, ranges to skip, jump table entry counts, `setjmp` and `longjmp` when the analysis
cannot find them, functions the port replaces, and hooks at single instructions. Paths are relative to the config. The output gets a
copy of this repository's `Cargo.lock`, so it builds with the same dependency versions. It may lie
inside another Cargo workspace, such as the port's, only if that workspace lists it under
`exclude`: otherwise Cargo takes the generated crates for members of that workspace, and their
build fails.

`ferrum recomp` warns about what the config may need to fix: unresolved jump tables, paths that run
off the end of a function, and function boundaries that look wrong.

A cold build of a large game uses every core and several GB of memory for minutes. Pass `-j` to
Cargo to keep the machine usable.

## Writing a port

A port is a binary crate that depends on the generated root crate and on `ferrum-runtime`.
`ferrum init` writes one whose `main.rs` does this, leaving out the stack, the thread setup and the
heap that a real kernel provides:

```rust
use ferrum_runtime::{FnTable, HookTable, Kernels, Memory, PpcContext, Xam, Xboxkrnl, enter};

struct Kernel;

// Every kernel export is a trait method whose default panics with its name and the caller's LR.
// Implement them as the game reaches them.
impl Xboxkrnl for Kernel {}
impl Xam for Kernel {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xex = ferrum_xex::Xex::parse(&std::fs::read("game/default.xex")?)?;
    let mem = Memory::new()?;
    mem.write_bytes(xex.image.base, &xex.image.data);

    let mut table = FnTable::new();
    game_ppc::register(&mut table)?;
    // Replacements for the functions listed under [hooks] function:
    // table.set(0x82003000, my_memcpy)?;

    let hooks = HookTable::new(); // mid-asm hooks, by instruction address, installed with `set`
    let kernel = Kernel;
    let k = Kernels { krnl: &kernel, xam: &kernel, table: &table, hooks: &hooks };
    game_ppc::imports::load(&mem, &k);
    let missing = game_ppc::hooks::missing(&table, &hooks);
    if !missing.is_empty() {
        return Err(format!("hooks not installed: {missing:?}").into());
    }

    let mut ctx = PpcContext::new();
    let entry = table.get(xex.image.entry).ok_or("the entry point was not recompiled")?;
    enter(entry, &mut ctx, &mem, &k);
    Ok(())
}
```

Every guest function has the signature `fn(&mut PpcContext, &Memory, &Kernels)`. A port's
replacements and kernel functions use it too: they read their arguments from `ctx.r[3]` and up and
put the result in `ctx.r[3]`.

## Limitations

- No game has run yet, so the generated code has only been checked by the test suites below.
- One module per run. Games that load further modules (DLLs or other XEX files) need each one
  recompiled and registered separately, which nothing does yet.
- No `.xexp` patches.
- No C++ exceptions: `RtlUnwind` and the funclets of `try` blocks are not supported.
- Floating-point arithmetic always rounds to nearest, and FPSCR exceptions never trap.
- The integer forms that set OV (`addo`, `subfo` and the rest) have no emitter yet, because no
  test covers them; `ferrum recomp` lists any it meets.
- On Windows, each `Memory` commits 4 GiB of address space against the system commit limit
  (physical memory plus page file), although untouched pages use no RAM. On Linux the mapping uses
  `MAP_NORESERVE`. The first 64 KiB are inaccessible, so a null pointer access crashes at once.

## Testing

```sh
cargo test --workspace
```

- The decoder is compared with the objdump listings of Xenia's PowerPC test suite, line by line.
- `ferrum-harness` recompiles every test file of that suite and 96 integer test files of Xenia
  Canary, runs them through generated code, and compares registers and memory with the values the
  files annotate: integer, floating point, VMX, VMX128 and a jump table. Two cases are excluded,
  with the reason in `manifest.toml`: one expects a rounding the ISA rules out, the other a
  misaligned `ldarx`, which the ISA leaves to the alignment interrupt. Synthetic
  programs cover what the suites leave out: calls, tail calls, save and restore routines, `setjmp`
  and `longjmp`, imports and hooks.
- `ferrum-scale` generates synthetic programs of any size to measure Cargo over the output; its
  test checks 300 functions.

The `trace` feature of `ferrum-runtime` checks every guest access against the memory regions the
port registers. It is slow, and meant for diagnosis:

```sh
cargo test -p ferrum-harness --features trace
```

CI runs `cargo fmt --check`, `cargo clippy -D warnings` and the tests, with and without `trace`, on
Linux and Windows. The binaries of the test suites are committed; regenerating them takes the
assembler described in [`tests/xenia-ppc/README.md`](tests/xenia-ppc/README.md), which building and
testing do not need.

## Repository layout

| Crate | What it does |
|---|---|
| `ferrum-xex` | XEX2 loader: headers, decryption, decompression, PE image |
| `ferrum-decoder` | Xenon instruction decoder and disassembler |
| `ferrum-analysis` | Function discovery, basic blocks, jump tables, save and restore routines |
| `ferrum-codegen` | Rust generation and the layout of the output workspace |
| `ferrum-runtime` | What generated code runs on: memory, context, function table, kernel traits |
| `ferrum` | The command line: `recomp`, `dump`, `disasm` |
| `ferrum-harness` | Runs the Xenia test suites through generated code (not published) |
| `ferrum-scale` | Synthetic workload for measuring Cargo over the output (not published) |

See [`CONTRIBUTING.md`](CONTRIBUTING.md) to contribute.

## Game content

This repository holds no game content and never will, nor any config of a particular game, which
belongs to its port. Use files from games you own.

## Third-party material

Parts of [Xenia](https://github.com/xenia-project/xenia) and
[Xenia Canary](https://github.com/xenia-canary/xenia-canary) are included under the BSD 3-Clause
license, Copyright (c) 2015, Ben Vanik:

- `crates/ferrum-xex/tables/xenia/`: the ordinal tables of `xboxkrnl.exe` and `xam.xex`, verbatim,
  with the license in [`LICENSE`](crates/ferrum-xex/tables/xenia/LICENSE). Binaries built from this
  repository contain them, so distributing such a binary requires reproducing that notice. The
  method list of the kernel traits, `crates/ferrum-runtime/src/kernel/exports.in`, is generated from
  them and carries the same notice, so the same applies to anything built with `ferrum-runtime`.
- `tests/xenia-ppc/`: Xenia's PowerPC test suite at commit
  `95a5c3ee250f80c3b9d139658649d9ffb6db3eec`, with its license; see its
  [`README.md`](tests/xenia-ppc/README.md).
- `tests/xenia-canary-ppc/`: 96 integer test files of Xenia Canary at commit
  `80cecb77b9666cb528e7cb81a462ad0b8ad7b109`, with its license; see its
  [`README.md`](tests/xenia-canary-ppc/README.md).

The VMX128 encodings and field layouts of the decoder follow Xenia's `ppc_opcode_table_gen.cc` and
`ppc_decode_data.h`, also under that license.

## Acknowledgements

Xenia's research into the Xbox 360, its kernel tables and its PowerPC test suite made this project
testable from the first instruction. [XenonRecomp](https://github.com/hedge-dev/XenonRecomp) showed that static
recompilation of Xbox 360 games works; it generates C++, and ferrum-recomp generates Rust.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project is dual-licensed as above, without any additional terms or conditions.
