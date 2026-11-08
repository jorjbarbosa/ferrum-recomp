# Integer tests from Xenia Canary

The `.s` files and `LICENSE` are third-party files from the
[Xenia Canary](https://github.com/xenia-canary/xenia-canary) project, copied byte for byte. They are
licensed under the BSD 3-Clause license in [`LICENSE`](LICENSE), not under the license of this
repository. Its text is the same as that of the Xenia suite under `tests/xenia-ppc/`:

    Copyright (c) 2015, Ben Vanik. All rights reserved.

| Files here | Files in Xenia Canary |
|---|---|
| `*.s` | `src/xenia/cpu/ppc/testing/*.s` |
| `LICENSE` | `LICENSE` |

Taken from Xenia Canary commit `80cecb77b9666cb528e7cb81a462ad0b8ad7b109`, on its branch
`canary_experimental`. Do not edit the `.s` files.

## Which files

[`manifest.txt`](manifest.txt) names the 96 files, one per line. They are the `instr_*.s` files of
that commit that are integer only and assemble with the tools below:

- not already in `tests/xenia-ppc/`, which stays at its own Xenia commit;
- not `instr__gen_*`, `instr_f*`, `instr_v*` or `*128`, and touching no FPR, VR, FPSCR or VSCR,
  which leaves out `instr_lfd`, `instr_lfs`, `instr_stfd`, `instr_stfs`, `instr_stfiwx`,
  `instr_mcrfs`, `instr_mffsx`, `instr_mtfsfix`, `instr_mtfsfx`, `instr_mfvscr` and the VMX loads and
  stores;
- minus `instr_mcrxr` and `instr_mftb`, which the pinned assembler rejects with `-mpower7`.

They are here because the Xenia suite has no test of a load, a store, the reservation, the CR
logical instructions, `mcrf`, `mtcrf` or `rldimi`; these files cover 80 instructions it does not.
Their expected values are the output of Canary's own emulator, not an independent reference, so a
pass means that two implementations agree. Where an expectation contradicts the ISA books, the case
goes on the exclusion list of `crates/ferrum-harness/manifest.toml` with the reason.

## Generated files

The `.bin`, `.map` and `.dis` files are derived from the sources with the same tools, flags and
link step as the Xenia suite (see `tests/xenia-ppc/README.md`), and come under the same license.

    python scripts/regen-xenia-ppc.py --binutils DIR --suite canary            # rewrite them
    python scripts/regen-xenia-ppc.py --binutils DIR --suite canary --check    # compare only
    python scripts/regen-xenia-ppc.py --binutils DIR --suite canary --import-from CANARY_GIT_DIR

`--import-from` copies the files that `manifest.txt` names out of a clone of Xenia Canary, taking
the bytes of the git objects at the commit above. A partial clone (`--filter=blob:none`) of that
commit is enough.

## What to keep in mind when using them

- The expected values are what Canary's own emulator produced, not an independent reference.
- 110 `MEMORY_IN` and `MEMORY_OUT` lines write their bytes as `[AB, CD, ...]`. Xenia's parser reads
  them two characters at a time, skipping spaces, so `[AB, CD` becomes `00 0B CD 00`, and the
  expected values were produced that way: `test_lwz_1` expects `0x000BCD00`. Each of those lines
  ends in a lone `]`.
- `instr_mfmsr` expects the MSR value `0x9030` that Canary's test thread starts with.
- Some files define an assembler macro, `make_full_test_constant`, before their tests.
