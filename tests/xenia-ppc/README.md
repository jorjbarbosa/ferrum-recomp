# Xenia PPC test suite

The `.s` files and `LICENSE` are third-party files from the
[Xenia](https://github.com/xenia-project/xenia) project, copied byte for byte. They are licensed
under the BSD 3-Clause license in [`LICENSE`](LICENSE), not under the license of this repository:

    Copyright (c) 2015, Ben Vanik. All rights reserved.

| Files here | Files in Xenia |
|---|---|
| `*.s` | `src/xenia/cpu/ppc/testing/*.s` |
| `LICENSE` | `LICENSE` |

Taken from Xenia commit `95a5c3ee250f80c3b9d139658649d9ffb6db3eec`. Do not edit the `.s` files. To
refresh them, run the script below with `--import-from`, which takes the bytes of the git objects:
a Windows checkout of Xenia shows them with CRLF line endings, but they are LF in its repository.

## Generated files

The `.bin`, `.map` and `.dis` files are derived from those sources by the tools below, and come
under the same license. Xenia does not keep them in its repository, so they were generated once and
committed here. Building and testing this repository needs neither the tools nor the game.

    python scripts/regen-xenia-ppc.py --binutils DIR            # rewrite the generated files
    python scripts/regen-xenia-ppc.py --binutils DIR --check    # compare, change nothing

The same script, with `--suite canary`, generates the files of `tests/xenia-canary-ppc/`.

The tools are GNU Binutils 2.24 with the vmx128 patch, from
[`benvanik/binutils-ppc-cygwin`](https://github.com/benvanik/binutils-ppc-cygwin) at commit
`6f3f15db908d339472db7be450f7c58bb71545cc`, the submodule Xenia pins at the commit above. Their
output is plain data; the tools themselves are not part of this repository.

The steps are those of `GenTestsCommand` in Xenia's `xenia-build`:

    powerpc-none-elf-as -a32 -be -mregnames -mpower7 -maltivec -mvsx -mvmx128 -R -oNAME.o NAME.s
    powerpc-none-elf-objdump --adjust-vma=0x100000 -Mpower7 -Mvmx128 -D -EB NAME.o > NAME.dis
    powerpc-none-elf-ld "-A powerpc:common32" -melf32ppc -EB -nostdlib --oformat=binary \
        -Ttext=0x80000000 -e0x80000000 -oNAME.bin NAME.o
    powerpc-none-elf-nm --numeric-sort NAME.o > NAME.map

The first 4 lines of each `.dis` are dropped, because they name the object file. There is one
difference from `gentests`, which only takes `instr_*` and `seq_*` files: the script takes every
`.s`, so that `ppc_testing_native_thunks.s` is covered as well. That file is the register setup of
Xenia's native test runner, not a test, so a test harness should skip it.

## What to keep in mind when using them

- The `.dis` comes from the object file and the `.bin` from the linked image at `0x80000000`, so
  they differ where a relocation applies. `seq_jumptable_constants` is the one file where it shows.
- The `.dis` of `instr_vavgsh`, `instr_vpkpx` and `instr_vpkuhum128` are empty, because all the
  instructions of those sources are commented out.
- objdump 2.24 prints `.long` for some real instructions that `as` assembles, which affects
  `instr_vcmpxxfp.dis` and `instr_vsubshs.dis`. `crates/ferrum-decoder/tests/xenia_dis.rs` lists
  those instructions and compares their lines with the `.s` source instead.
