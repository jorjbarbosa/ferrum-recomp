# Ordinal tables from Xenia

`xboxkrnl_table.inc` and `xam_table.inc` map the ordinals of the `xboxkrnl.exe` and `xam.xex`
exports to their names and kinds. They are third-party files from the
[Xenia](https://github.com/xenia-project/xenia) project, copied byte for byte, and are licensed
under the BSD 3-Clause license in [`LICENSE`](LICENSE), not under the license of this repository:

    Copyright (c) 2015, Ben Vanik. All rights reserved.

| File here | File in Xenia |
|---|---|
| `xboxkrnl_table.inc` | `src/xenia/kernel/xboxkrnl/xboxkrnl_table.inc` |
| `xam_table.inc` | `src/xenia/kernel/xam/xam_table.inc` |
| `LICENSE` | `LICENSE` |

Taken from Xenia commit `95a5c3ee250f80c3b9d139658649d9ffb6db3eec`. Both tables last changed in
commit `997d0555dbd6358dffd2950097424993763051af`.

`ferrum-xex` embeds the tables with `include_str!` and parses them at run time (see
`src/ordinals.rs`), so they stay verbatim and can be refreshed by copying them again.
`ferrum-runtime` derives the methods of its kernel traits from them, in
`crates/ferrum-runtime/src/kernel/exports.in`; after a refresh, regenerate that file with
`FERRUM_BLESS=1 cargo test -p ferrum-runtime --test kernel_exports`. A binary
built from this crate contains them, so its distribution has to reproduce the notice above and the
license text, as the license requires.
