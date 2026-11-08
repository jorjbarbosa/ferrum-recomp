// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! What the tests of the CLI share: a synthetic XEX and scratch directories.

use std::fs;
use std::path::PathBuf;

use ferrum_xex::fixtures::sample::{SampleLayout, THUNKS_OFFSET};

/// The size of `.text` in the sample.
const TEXT_SIZE: usize = 0x800;

/// A sample whose `.text` holds the given words at the given offsets, zero elsewhere apart from
/// the import thunks, so that the sweep of the gaps finds nothing else.
fn sample(code: &[(usize, &[u32])]) -> Vec<u8> {
    let layout = SampleLayout::default();
    let mut builder = layout.builder();
    let text = (layout.text() - layout.base) as usize;
    let thunks = text + THUNKS_OFFSET as usize;
    builder.image[text..thunks].fill(0);
    // Three thunks of 16 bytes, for the three imported functions of the sample.
    builder.image[thunks + 0x30..text + TEXT_SIZE].fill(0);
    for &(offset, words) in code {
        for (index, word) in words.iter().enumerate() {
            let at = text + offset + 4 * index;
            builder.image[at..at + 4].copy_from_slice(&word.to_be_bytes());
        }
    }
    builder.build().bytes
}

/// The code of the tests: the three `.pdata` functions of the sample, a call to the first thunk
/// (`ExCreateThread`), and one function that only the sweep finds.
pub fn code() -> Vec<u8> {
    sample(&[
        // .text+0x00: bl .text+0x10; bl .text+0x400; li r3,0; blr
        (0x00, &[0x4800_0011, 0x4800_03FD, 0x3860_0000, 0x4E80_0020]),
        // .text+0x10: li r3,1; blr
        (0x10, &[0x3860_0001, 0x4E80_0020]),
        // .text+0x30: li r3,2; blr
        (0x30, &[0x3860_0002, 0x4E80_0020]),
        // .text+0x40: li r3,3; blr
        (0x40, &[0x3860_0003, 0x4E80_0020]),
    ])
}

/// A fresh directory outside every Cargo workspace.
pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ferrum-test-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}
